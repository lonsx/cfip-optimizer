// cfip-opt —— Cloudflare 边缘 IP 优选（Go 单二进制版）
//
// 功能语义对齐飞牛 NAS 上的 cf-dns-select（ghcr.io/neon9809/cf-dns-select）：
// 在同一套规则下做「多轮延迟 → 地区过滤 → 多轮下载测速 → 写 AdGuard 重写表」，
// 并补齐了原应用没有的地址族对半分名额、样本标准差、故障快速轮换。
//
// 技术形态是纯 Go 标准库的静态单文件二进制，零运行时依赖：
// 放在飞牛原生应用的 bin/ 下直接由 fnOS 拉起，不需要 Docker。
//
// 环境变量：
//
//	CFIP_DATA           数据目录（config.json / ip.txt / ipv6.txt / last_result.json）
//	CFIP_SOCK           监听 Unix 域套接字（飞牛原生应用模式，优先于 CFIP_LISTEN）
//	CFIP_LISTEN         监听 TCP 地址，默认 127.0.0.1:8787
//	CFIP_ALLOWED_CIDRS  允许访问的来源网段（逗号分隔）。绑非环回地址时必填，
//	                    否则拒绝启动——Dashboard 里存着 AdGuard 凭据，不能裸奔。
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"cfip-opt/internal/engine"
	"cfip-opt/internal/server"
)

func main() {
	// 子命令：供飞牛 ctl_stop 脚本与运维使用（见 console.go）
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "daemon":
			os.Exit(cmdDaemon())
		case "stop":
			os.Exit(cmdStop())
		case "status":
			os.Exit(cmdStatus())
		}
	}

	dataDir := os.Getenv("CFIP_DATA")
	if dataDir == "" {
		dataDir = defaultDataDir()
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("创建数据目录失败：%v", err)
	}

	// 首次启动写入默认配置与 IP 段文件，避免用户面对空目录
	seedDefaults(dataDir)

	// ---- 飞牛原生应用模式：只监听 Unix 套接字，不占端口 ----
	//
	// 这种模式下连接方只可能是本机的 CGI 网关，来源天然可信，
	// 不需要 CFIP_ALLOWED_CIDRS（外部根本连不到这个套接字）。
	if sock := strings.TrimSpace(os.Getenv("CFIP_SOCK")); sock != "" {
		app := server.NewWithGate(dataDir, "")
		installStop(app)
		fmt.Printf("cfip-opt 启动：unix:%s  数据目录 %s\n", sock, dataDir)
		if err := app.ListenAndServeUnix(sock); err != nil {
			log.Fatalf("服务退出：%v", err)
		}
		return
	}

	listen := os.Getenv("CFIP_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8787"
	}
	host, port := server.ParseListen(listen)
	addr := fmt.Sprintf("%s:%d", host, port)

	// ---- 安全门禁：绑非环回地址时必须显式声明允许来源 ----
	//
	// 与原应用 cf-dns-select 的 DSA_ALLOWED_CIDRS 同一个思路：宁可起不来，
	// 也不要让一个存着 AdGuard 凭据的 Dashboard 裸奔在网上。
	cidrs := strings.TrimSpace(os.Getenv("CFIP_ALLOWED_CIDRS"))
	if cidrs == "" && !isLoopbackHost(host) {
		log.Fatalf("[安全门禁] 监听地址 %s 不是环回地址，必须通过环境变量 "+
			"CFIP_ALLOWED_CIDRS 显式配置允许访问 Dashboard 的来源网段"+
			"（例：192.168.0.0/16,10.0.0.0/8）。\n"+
			"若只想本机访问，把 CFIP_LISTEN 改成 127.0.0.1:8787 即可。", addr)
	}

	app := server.NewWithGate(dataDir, cidrs)
	installStop(app)

	gateNote := "不限（仅环回）"
	if cidrs != "" {
		gateNote = cidrs
	}
	fmt.Printf("cfip-opt 启动：http://%s:%d  数据目录 %s  来源门禁 %s\n", host, port, dataDir, gateNote)
	if err := app.ListenAndServe(addr); err != nil {
		log.Fatalf("服务退出：%v", err)
	}
}

// installStop 优雅退出：先通知后台协程收工，再退出进程。
func installStop(app *server.App) {
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		app.Stop()
		os.Exit(0)
	}()
}

// isLoopbackHost 判断监听主机是否只对本机开放。
func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func defaultDataDir() string {
	// 飞牛布局有两处入口，都要能正确定位 @appdata/<app>：
	//   /volN/@appcenter/<app>/bin/<app>     ← 真实安装位置（os.Executable 会解析掉软链）
	//   /var/apps/<app>/target/bin/<app>     ← 应用中心经 target 软链调用
	// 注意 @appcenter/<app> 的上一级是 @appcenter 本身，祖父才是卷根 /volN，
	// @appdata 就在卷根下 —— 少往上数一级会得到 <卷>@appcenter/@appdata/<app>（不存在），
	// 表现为"配置丢失"（其实读到的是另一份空配置）。
	if exe, err := os.Executable(); err == nil {
		root := filepath.Dir(filepath.Dir(exe))

		// /var/apps/<app>/target 布局：同级 var 就是 @appdata 软链
		if filepath.Base(root) == "target" {
			if v := filepath.Join(filepath.Dir(root), "var"); dirExists(v) {
				return v
			}
		}

		// @appcenter 布局：.../@appcenter/<app> → 祖父目录是卷根
		if parent := filepath.Dir(root); filepath.Base(parent) == "@appcenter" {
			return filepath.Join(filepath.Dir(parent), "@appdata", appName)
		}

		return filepath.Join(filepath.Dir(exe), "data")
	}
	return "data"
}

// seedDefaults 只补缺失文件，绝不覆盖已有内容。
func seedDefaults(dataDir string) {
	cfgPath := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		store := engine.NewConfigStore(dataDir)
		_ = store.Save(engine.DefaultConfig())
	}
	writeIfMissing(filepath.Join(dataDir, "ip.txt"), defaultIPv4)
	writeIfMissing(filepath.Join(dataDir, "ipv6.txt"), defaultIPv6)
}

func writeIfMissing(p, content string) {
	if _, err := os.Stat(p); err == nil {
		return
	}
	_ = os.WriteFile(p, []byte(content), 0o644)
}

// defaultIPv4 Cloudflare 官方公布的 IPv4 段（https://www.cloudflare.com/ips-v4）
const defaultIPv4 = `173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
`

// defaultIPv6 Cloudflare 官方公布的 IPv6 段（https://www.cloudflare.com/ips-v6）
const defaultIPv6 = `2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
`
