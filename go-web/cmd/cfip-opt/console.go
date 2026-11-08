// 面向飞牛应用中心的进程控制：后台启动 / 停止 / 状态查询。
//
// 为什么不交给 systemd：飞牛原生应用（fPK）的第二方程序不由 systemd 托管，
// 而是由应用中心的 ctl_stop 脚本负责起停。所以二进制自带一个轻量的
// 「守护式后台化」：父进程 fork 出的子进程写 pid 文件，父进程立刻返回。
// 这样 ctl_stop 里的 start 命令不会把安装流程卡住。
//
// 这是 subcommand 模式，和默认的「前台跑服务」区分开：
//
//	cfip-opt                  前台运行（默认）
//	cfip-opt daemon           后台运行，写 pid 文件
//	cfip-opt stop             按 pid 文件停进程
//	cfip-opt status           打印运行状态，退出码 0=在跑 3=没跑
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	stateRunning  = 0
	stateStopped  = 3
	stateUnknown  = 4
	stopWaitLimit = 8 * time.Second
)

// resolveVarDir 返回 @appdata 目录（数据、pid、日志都在这）。
//
// 二进制可能从多处被调用，必须逐一识别，否则 status 会误判为「未运行」
// （曾导致应用中心把应用置成 start 状态、桌面图标消失）：
//
//	1. /var/apps/<app>/target/bin/<app>   ← 应用中心经 target 软链调用
//	   注意：os.Executable() 会解析软链，实际拿到的是 @appcenter 真实路径，
//	   所以这个分支通常不会命中；保留作兜底。
//	2. /volN/@appcenter/<app>/bin/<app>   ← 真实安装位置（最常见）
//	   此时 root = /volN/@appcenter/<app>，其父是 @appcenter，祖父才是 /volN，
//	   数据在 /volN/@appdata/<app>。曾错写成 dirname(root)，得到
//	   /volN/@appcenter/@appdata/<app>，读不到 pid → status 恒为 stopped。
//	3. 开发机上的 bin/data 布局          ← 兜底为 exe 同级的 data 目录。
func resolveVarDir() string {
	if d := strings.TrimSpace(os.Getenv("CFIP_DATA")); d != "" {
		return d
	}
	exe, err := os.Executable()
	if err != nil {
		return "data"
	}
	root := filepath.Dir(filepath.Dir(exe)) // .../<app>/bin/<app> → .../<app>

	// 1) /var/apps/<app>/target 布局：同级 var 软链指向 @appdata
	if filepath.Base(root) == "target" {
		if v := filepath.Join(filepath.Dir(root), "var"); dirExists(v) {
			return v
		}
	}

	// 2) @appcenter 布局：.../@appcenter/<app> → 祖父目录是卷根，@appdata 在那下面
	if parent := filepath.Dir(root); filepath.Base(parent) == "@appcenter" {
		return filepath.Join(filepath.Dir(parent), "@appdata", appName)
	}

	// 3) /var/apps/<app> 布局（target 未被解析时）：同级 var
	if v := filepath.Join(filepath.Dir(root), "var"); dirExists(v) {
		return v
	}

	// 4) 兜底：exe 同级 data
	return filepath.Join(filepath.Dir(exe), "data")
}

// dirExists 判断路径是否为存在的目录（跟随软链）。
func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

const appName = "cfip-opt"

func pidPath() string { return filepath.Join(resolveVarDir(), appName+".pid") }
func sockPath() string {
	if s := strings.TrimSpace(os.Getenv("CFIP_SOCK")); s != "" {
		return s
	}
	return filepath.Join(resolveVarDir(), appName+".sock")
}

// readPID 读 pid 文件并校验进程确实存在（防 pid 复用误判）。
func readPID() (int, bool) {
	b, err := os.ReadFile(pidPath())
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, false
	}
	// 用 signal 0 探测：进程在则返回 nil 或 EPERM，不在则 ESRCH
	if err := syscall.Kill(pid, 0); err != nil {
		return pid, err == syscall.EPERM
	}
	return pid, true
}

// cmdDaemon 后台启动：自己再 exec 一次（带 CFIP_DAEMON_CHILD=1），
// 然后把子进程 pid 写盘。
func cmdDaemon() int {
	if pid, alive := readPID(); alive {
		fmt.Printf("%s 已在运行（pid %d），跳过启动\n", appName, pid)
		return 0
	}
	_ = os.MkdirAll(resolveVarDir(), 0o755)
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "取不到自身路径：%v\n", err)
		return 1
	}

	env := os.Environ()
	env = append(env, "CFIP_DAEMON_CHILD=1")
	if os.Getenv("CFIP_SOCK") == "" {
		env = append(env, "CFIP_SOCK="+sockPath())
	}

	logf, err := os.OpenFile(filepath.Join(resolveVarDir(), appName+".log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打不开日志文件：%v\n", err)
		return 1
	}
	defer logf.Close()

	cmd := exec.Command(exe)
	cmd.Env = env
	cmd.Dir = resolveVarDir()
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	// Setsid：脱离当前会话，ctl_stop 脚本退出后子进程继续活着
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		return 1
	}

	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath(), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写 pid 文件失败：%v\n", err)
	}
	// 等套接字就绪再返回，避免紧接着的 CGI 请求打到空档
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath()); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("%s 已后台启动（pid %d）\n", appName, pid)
	return 0
}

// cmdStop 先 TERM 再 KILL，接口文档里 ctl_stop 必须可靠返回。
func cmdStop() int {
	pid, alive := readPID()
	if !alive {
		fmt.Printf("%s 未在运行\n", appName)
		_ = os.Remove(pidPath())
		_ = os.Remove(sockPath())
		return 0
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	deadline := time.Now().Add(stopWaitLimit)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			fmt.Printf("%s 已停止（pid %d）\n", appName, pid)
			_ = os.Remove(pidPath())
			_ = os.Remove(sockPath())
			return 0
		}
		time.Sleep(150 * time.Millisecond)
	}
	// 8 秒还没退：可能在写文件，强制收掉
	_ = syscall.Kill(pid, syscall.SIGKILL)
	fmt.Printf("%s 强制结束（pid %d）\n", appName, pid)
	_ = os.Remove(pidPath())
	_ = os.Remove(sockPath())
	return 0
}

// cmdStatus 供 UI / 脚本查询。
func cmdStatus() int {
	pid, alive := readPID()
	if alive {
		fmt.Printf("running pid=%d sock=%s\n", pid, sockPath())
		return stateRunning
	}
	fmt.Println("stopped")
	return stateStopped
}
