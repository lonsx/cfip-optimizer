// Package engine —— Cloudflare IP 优选测速引擎。
//
// 技术路线对齐开源项目 CloudflareSpeedTest（XIU2/CloudflareSpeedTest）：
//   - 纯标准库，不引入任何第三方依赖，最终产出静态单文件二进制
//   - IP 段随机取样 → 并发测延迟 → cf-colo 地区过滤 → 下载测速取带宽
//   - 延迟测速支持 TCP 握手 / TLS 握手 / HTTPing 三种口径
//
// 在本项目里额外补上的能力（原项目没有）：
//   - latency_cap 按地址族对半分名额（v4 / v6 互不挤占）
//   - fast_fail 连续失败提前放弃剩余轮次
//   - IPv6 出口真实可达性预检
//   - 最终严格按实测带宽最大者胜出
package engine

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UA 与 Python 版保持一致，避免 CF 对未知 UA 做差异化处理。
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36"

// Chunk 下载读取块大小（64KB，与 CFST 一致）。
const Chunk = 64 * 1024

// V6HugePrefix 短于等于此长度的 IPv6 前缀视为「聚合段」。
const V6HugePrefix = 32

// ---------------------------------------------------------------- 统计工具

// MeanSigma 返回算术平均与样本标准差（n-1）。样本数 < 2 时 sigma 为 NaN 语义（用 ok 标记）。
func MeanSigma(values []float64) (mean float64, sigma float64, hasSigma bool, ok bool) {
	if len(values) == 0 {
		return 0, 0, false, false
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))
	if len(values) < 2 {
		return mean, 0, false, true
	}
	var sq float64
	for _, v := range values {
		d := v - mean
		sq += d * d
	}
	sigma = math.Sqrt(sq / float64(len(values)-1))
	return mean, sigma, true, true
}

// IsV6 判断地址串是否为 IPv6。
func IsV6(ip string) bool {
	return strings.Contains(ip, ":")
}

// ParseIP 解析地址，失败返回 nil。
func ParseIP(s string) net.IP {
	return net.ParseIP(strings.TrimSpace(s))
}

// BlockKey 取样分块的键：IPv4 用 /24，IPv6 用 /64，与地区库聚合口径一致。
func BlockKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	return fmt.Sprintf("%x:%x:%x:%x::/64",
		uint16(v6[0])<<8|uint16(v6[1]),
		uint16(v6[2])<<8|uint16(v6[3]),
		uint16(v6[4])<<8|uint16(v6[5]),
		uint16(v6[6])<<8|uint16(v6[7]))
}

// ---------------------------------------------------------------- IP 池展开

// CIDR 表示一条已解析的网段。
type CIDR struct {
	Net    *net.IPNet
	V6     bool
	Bits   int   // 前缀长度
	Start  *big.Int
	End    *big.Int
	Span   *big.Int // 可用主机数
}

func parseCIDRLine(line string) (*CIDR, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}
	// 允许裸 IP：补成 /32 或 /128
	if !strings.Contains(line, "/") {
		ip := net.ParseIP(line)
		if ip == nil {
			return nil, false
		}
		if ip.To4() != nil {
			line += "/32"
		} else {
			line += "/128"
		}
	}
	_, n, err := net.ParseCIDR(line)
	if err != nil {
		return nil, false
	}
	c := &CIDR{Net: n, V6: strings.Contains(line, ":"), Bits: 0}
	ones, bits := n.Mask.Size()
	c.Bits = ones
	c.Start = ipToBig(n.IP, c.V6)
	c.Span = c.span(bits - ones)
	c.End = new(big.Int).Add(c.Start, new(big.Int).Sub(c.Span, big.NewInt(1)))
	return c, true
}

func (c *CIDR) span(hostBits int) *big.Int {
	if hostBits <= 0 {
		return big.NewInt(1)
	}
	if hostBits > 128 {
		hostBits = 128
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
}

func ipToBig(ip net.IP, v6 bool) *big.Int {
	if !v6 {
		if v4 := ip.To4(); v4 != nil {
			return new(big.Int).SetBytes(v4)
		}
	}
	return new(big.Int).SetBytes(ip.To16())
}

func bigToIP(b *big.Int, v6 bool) net.IP {
	n := 16
	if !v6 {
		n = 4
	}
	buf := b.Bytes()
	if len(buf) > n {
		buf = buf[len(buf)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(buf):], buf)
	return net.IP(out)
}

// randBig 返回 [0, max) 上的均匀随机大整数。max 必须 > 0。
func randBig(max *big.Int) *big.Int {
	if max.Cmp(big.NewInt(1)) <= 0 {
		return big.NewInt(0)
	}
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return big.NewInt(0)
	}
	return v
}

// ParseCIDRText 解析多行 CIDR 文本。
func ParseCIDRText(text string) []*CIDR {
	var out []*CIDR
	for _, ln := range strings.Split(text, "\n") {
		if c, ok := parseCIDRLine(ln); ok {
			out = append(out, c)
		}
	}
	return out
}

// ExpandCandidates 把 CIDR 文本展开为待测 IP 列表。
//
// testAll 为 false 时：IPv4 每个 /24 随机取 1 个；IPv6 每条前缀随机取 v6PerCIDR 个。
// testAll 为 true 时：逐一枚举 IPv4（受 cap 保护）。
//
// IPv6 特殊处理：ipv6.txt 里同时存在 2606:4700::/32 这类聚合段和一批 /48。
// /32 里 2^96 个地址绝大多数不承载服务，纯随机取几乎全连不上，且它完全覆盖
// 后面所有 /48 造成重复。因此聚合段只在其「未被细段覆盖」的剩余空间取样。
func ExpandCandidates(text string, testAll bool, capN int, v6PerCIDR int) []string {
	if capN <= 0 {
		capN = 20000
	}
	nets := ParseCIDRText(text)

	var v4Nets, v6Nets []*CIDR
	var v6Fine [][2]*big.Int
	for _, c := range nets {
		if c.V6 {
			v6Nets = append(v6Nets, c)
			if c.Bits > V6HugePrefix {
				v6Fine = append(v6Fine, [2]*big.Int{c.Start, c.End})
			}
		} else {
			v4Nets = append(v4Nets, c)
		}
	}
	inFine := func(v *big.Int) bool {
		for _, r := range v6Fine {
			if v.Cmp(r[0]) >= 0 && v.Cmp(r[1]) <= 0 {
				return true
			}
		}
		return false
	}

	expandV4 := func(targetCap int) []string {
		if targetCap <= 0 || len(v4Nets) == 0 {
			return nil
		}
		out := make([]string, 0, targetCap)
		seen := make(map[string]struct{}, targetCap)
		push := func(s string) bool {
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				out = append(out, s)
			}
			return len(out) >= targetCap
		}

		for _, c := range v4Nets {
			blocks := c.blocks24()
			for _, b := range blocks {
				if testAll {
					cnt := new(big.Int).Set(b.Span)
					lo := new(big.Int).Set(b.Start)
					hi := new(big.Int).Add(b.Start, new(big.Int).Sub(b.Span, big.NewInt(1)))
					if b.Span.Cmp(big.NewInt(2)) > 0 {
						lo.Add(lo, big.NewInt(1))
						hi.Sub(hi, big.NewInt(1))
						cnt = new(big.Int).Add(new(big.Int).Sub(hi, lo), big.NewInt(1))
					}
					for i := big.NewInt(0); i.Cmp(cnt) < 0; i.Add(i, big.NewInt(1)) {
						v := new(big.Int).Add(lo, i)
						if push(bigToIP(v, false).String()) {
							return out
						}
					}
					continue
				}
				off := randBig(b.Span)
				v := new(big.Int).Add(b.Start, off)
				if push(bigToIP(v, false).String()) {
					return out
				}
			}
		}
		return out
	}

	expandV6 := func(targetCap int) []string {
		if targetCap <= 0 || len(v6Nets) == 0 {
			return nil
		}
		out := make([]string, 0, targetCap)
		seen := make(map[string]struct{}, targetCap)
		push := func(s string) bool {
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				out = append(out, s)
			}
			return len(out) >= targetCap
		}

		want := v6PerCIDR
		if want < 1 {
			want = 1
		}
		for _, c := range v6Nets {
			w := want
			if c.Bits <= V6HugePrefix && len(v6Fine) > 0 {
				w = w / 3
				if w < 1 {
					w = 1
				}
				got := 0
				for try := 0; try < w*40 && got < w; try++ {
					off := randBig(c.Span)
					v := new(big.Int).Add(c.Start, off)
					if inFine(v) {
						continue
					}
					got++
					if push(bigToIP(v, true).String()) {
						return out
					}
				}
				continue
			}
			for i := 0; i < w; i++ {
				off := randBig(c.Span)
				v := new(big.Int).Add(c.Start, off)
				if push(bigToIP(v, true).String()) {
					return out
				}
			}
		}
		return out
	}

	// 仅有一族时直接展开
	if len(v4Nets) == 0 {
		return expandV6(capN)
	}
	if len(v6Nets) == 0 {
		return expandV4(capN)
	}

	// 两族并存：按名额对半分分别展开，避免单族（尤其 testAll 模式下的巨量 IPv4）把总名额全部吃光
	cap6 := capN / 2
	out6 := expandV6(cap6)

	// v6 展开不足 half 时的余量自动让渡给 v4
	cap4 := capN - len(out6)
	out4 := expandV4(cap4)

	// 若 v4 展开后仍有名额且 v6 还有余力，二次补充
	if left := capN - len(out4) - len(out6); left > 0 && len(out6) == cap6 {
		extra6 := expandV6(cap6 + left)
		if len(extra6) > len(out6) {
			out6 = extra6
		}
	}

	out := make([]string, 0, len(out4)+len(out6))
	out = append(out, out4...)
	out = append(out, out6...)
	return out
}

type block24 struct {
	Start *big.Int
	Span  *big.Int
}

// blocks24 把 IPv4 网段按 /24 切开。
func (c *CIDR) blocks24() []block24 {
	if c.Bits >= 24 {
		return []block24{{c.Start, c.Span}}
	}
	// 每个 /24 = 256 个地址
	var out []block24
	n := new(big.Int).Div(c.Span, big.NewInt(256))
	if n.Cmp(big.NewInt(0)) <= 0 {
		return []block24{{c.Start, c.Span}}
	}
	limit := n.Int64()
	if limit > 70000 {
		limit = 70000
	}
	for i := int64(0); i < limit; i++ {
		st := new(big.Int).Add(c.Start, new(big.Int).Mul(big.NewInt(i), big.NewInt(256)))
		out = append(out, block24{st, big.NewInt(256)})
	}
	return out
}

// ---------------------------------------------------------------- 连接与探测

// dialTCP 按地址族建连。IPv6 必须显式 tcp6，否则部分平台会把字面量地址当 v4 解析。
func dialTCP(ip string, port int, timeout time.Duration) (net.Conn, error) {
	network := "tcp4"
	if IsV6(ip) {
		network = "tcp6"
	}
	d := net.Dialer{Timeout: timeout}
	return d.Dial(network, net.JoinHostPort(ip, strconv.Itoa(port)))
}

// TCPRTT 一次 TCP 建连耗时（毫秒），失败返回 (0,false)。
func TCPRTT(ip string, port int, timeout time.Duration) (float64, bool) {
	t0 := time.Now()
	c, err := dialTCP(ip, port, timeout)
	if err != nil {
		return 0, false
	}
	ms := float64(time.Since(t0).Microseconds()) / 1000.0
	c.Close()
	return ms, true
}

// TLSConfig 返回测速使用的 TLS 配置。
// 不校验证书：测的是「能不能走到对端边缘节点」，边缘节点证书与 SNI 一致但
// 逐条链校验会额外增加 RTT 噪声，且部分 IP 的证书链在国内缺中间证书。
func TLSConfig(sni string) *tls.Config {
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
}

// TLSRTT 一次 TLS 握手耗时（毫秒），失败返回 (0,false)。
//
// 为什么需要它：很多家用网络（旁路由 TPROXY / 运营商透明代理）会把 TCP SYN
// 在本地直接应答，TCP ping 永远只有 0.5~1ms 测不出节点差异。
// TLS 握手必须真的走到对端才能完成，是这种场景下唯一有区分度的指标。
func TLSRTT(ip string, port int, sni string, timeout time.Duration) (float64, bool) {
	c, err := dialTCP(ip, port, timeout)
	if err != nil {
		return 0, false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	t0 := time.Now()
	tc := tls.Client(c, TLSConfig(sni))
	if err := tc.Handshake(); err != nil {
		return 0, false
	}
	ms := float64(time.Since(t0).Microseconds()) / 1000.0
	tc.Close()
	return ms, true
}

// IPv6ProbeHosts 探测目标：必须是「真有 AAAA 记录且国内可达」的域名。
//
// 踩过的坑：
//  1. cloudflare.com 本身没有 AAAA（只有 www.cloudflare.com 有），拿它做探针必然失败；
//  2. 2606:4700:4700::1111 是 1.1.1.1 的 v6 版，国内 443/2053/2083/8443 全被墙
//     （53/80 反而通），用它判断会把正常宽带误判为无 v6。
var IPv6ProbeHosts = []string{"speed.cloudflare.com", "www.cloudflare.com"}

var IPv6ProbePorts = []int{443, 80}

// IPv6Info IPv6 出口探测结果。
type IPv6Info struct {
	OK     bool    `json:"ok"`
	Reason string  `json:"reason"`
	Local  string  `json:"local"`
	Target string  `json:"target"`
	MS     float64 `json:"ms"`
}

// IPv6Available 探测当前网络能否真正建立到 Cloudflare 的 IPv6 连接。
func IPv6Available(timeout time.Duration, port int, extraHosts []string) IPv6Info {
	info := IPv6Info{}
	hosts := append([]string{}, extraHosts...)
	hosts = append(hosts, IPv6ProbeHosts...)
	hosts = dedupe(hosts)

	ports := make([]int, 0, 3)
	if port > 0 {
		ports = append(ports, port)
	}
	ports = append(ports, IPv6ProbePorts...)
	ports = dedupeInt(ports)

	lastErr := ""
	for _, host := range hosts {
		addrs, err := net.LookupIP(host)
		if err != nil {
			lastErr = fmt.Sprintf("%s 解析失败（%v）", host, err)
			continue
		}
		var v6addrs []string
		for _, a := range addrs {
			if a.To4() == nil && a.To16() != nil {
				v6addrs = append(v6addrs, a.String())
			}
		}
		if len(v6addrs) == 0 {
			lastErr = fmt.Sprintf("%s 无 AAAA 记录", host)
			continue
		}
		for _, addr := range dedupe(v6addrs) {
			for _, p := range ports {
				t0 := time.Now()
				c, err := dialTCP(addr, p, timeout)
				if err != nil {
					lastErr = fmt.Sprintf("[%s]:%d %v", addr, p, err)
					continue
				}
				c.Close()
				info.OK = true
				info.Local = addr
				info.Target = fmt.Sprintf("[%s]:%d", addr, p)
				info.MS = float64(time.Since(t0).Microseconds()) / 1000.0
				return info
			}
		}
	}
	if lastErr == "" {
		lastErr = "无可用目标"
	}
	info.Reason = "无法建立 IPv6 连接（最后错误：" + lastErr + "）"
	return info
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupeInt(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, v := range in {
		if v <= 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// NetCheck 探测本机网络是否存在 TCP 拦截 / 透明代理。
//
// 判定依据：向 RFC5737 文档测试网段（现实中无主机）发起 TCP 建连，
// 正常必须超时或被拒绝；若「秒连成功」说明 SYN 被中途设备应答了。
type NetCheck struct {
	Hijacked      bool     `json:"hijacked"`
	DeadReachable []string `json:"dead_reachable"`
	Advice        string   `json:"advice"`
}

func CheckNet(timeout time.Duration) NetCheck {
	dead := []string{"192.0.2.1", "198.51.100.7"}
	nc := NetCheck{DeadReachable: []string{}}
	for _, ip := range dead {
		t0 := time.Now()
		c, err := dialTCP(ip, 443, timeout)
		if err != nil {
			continue
		}
		ms := float64(time.Since(t0).Microseconds()) / 1000.0
		c.Close()
		if ms < 500 {
			nc.DeadReachable = append(nc.DeadReachable, ip)
		}
	}
	nc.Hijacked = len(nc.DeadReachable) > 0
	if nc.Hijacked {
		nc.Advice = "检测到 TCP 拦截/透明代理：本机发出的 SYN 在本地就被应答，" +
			"ping 模式延迟全部集中在 1ms 以内、没有区分度。" +
			"建议改用 TLS 模式（握手必须走到对端才能完成）或 httping 模式。"
	}
	return nc
}

// ---------------------------------------------------------------- 结果行

// Result 一个 IP 的完整测速结果。字段名与前端 API 严格保持一致。
type Result struct {
	IP          string   `json:"ip"`
	Colo        string   `json:"colo"`
	DelayMS     *float64 `json:"delay_ms"`
	DelaySigma  *float64 `json:"delay_sigma"`
	DelayOK     int      `json:"delay_ok"`
	DelayRounds int      `json:"delay_rounds"`
	LossRate    float64  `json:"loss_rate"`
	SpeedKBps   *float64 `json:"speed_kbps"`
	SpeedSigma  *float64 `json:"speed_sigma"`
	SpeedOK     int      `json:"speed_ok"`
	SpeedRounds int      `json:"speed_rounds"`
}

// SpeedOrder 排序键：有速度的按速度降序在前；没速度的按延迟升序垫底。
// 这是「最优 = 实测带宽最大」这条规则的唯一实现，结果排序与写 DNS 选 IP 共用。
func SpeedOrder(a, b *Result) bool {
	hasA := a.SpeedKBps != nil && *a.SpeedKBps > 0
	hasB := b.SpeedKBps != nil && *b.SpeedKBps > 0
	if hasA != hasB {
		return hasA
	}
	if hasA && hasB && *a.SpeedKBps != *b.SpeedKBps {
		return *a.SpeedKBps > *b.SpeedKBps
	}
	da, db := math.Inf(1), math.Inf(1)
	if a.DelayMS != nil {
		da = *a.DelayMS
	}
	if b.DelayMS != nil {
		db = *b.DelayMS
	}
	if da != db {
		return da < db
	}
	return a.IP < b.IP
}

// SortBySpeed 按带宽降序排序结果。
func SortBySpeed(rows []*Result) {
	sort.SliceStable(rows, func(i, j int) bool { return SpeedOrder(rows[i], rows[j]) })
}

// Best 按「实测带宽最大」挑出最优一行；全部无速度数据时退化为延迟最低。
func Best(rows []*Result) *Result {
	var best *Result
	for _, r := range rows {
		if r == nil || r.IP == "" {
			continue
		}
		if best == nil || SpeedOrder(r, best) {
			best = r
		}
	}
	return best
}

// F 把 float64 取地址，便于构造 *float64 字段。
func F(v float64) *float64 { return &v }
