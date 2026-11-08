package engine

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ParsedURL 拆解测速地址。
type ParsedURL struct {
	Scheme string
	Host   string
	Path   string
	Port   int
}

// ParseTestURL 解析测速地址；scheme 缺省按 https 处理。
func ParseTestURL(raw string, defPort int) ParsedURL {
	out := ParsedURL{Scheme: "https", Path: "/", Port: defPort}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	if u.Scheme != "" {
		out.Scheme = u.Scheme
	}
	out.Host = u.Hostname()
	out.Path = u.EscapedPath()
	if out.Path == "" {
		out.Path = "/"
	}
	if u.RawQuery != "" {
		out.Path += "?" + u.RawQuery
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			out.Port = n
		}
	}
	return out
}

// IsCFSpeedHost 判断是否为 CF 官方测速域名（其 /__down 需要同源 Referer 才不给 403）。
func IsCFSpeedHost(host string) bool {
	h := strings.ToLower(host)
	return h == "speed.cloudflare.com" || strings.HasSuffix(h, ".speed.cloudflare.com")
}

// ParseColo 从响应头提取 Cloudflare / CDN 节点代码，口径与 Python 版一致。
func ParseColo(h *textproto.MIMEHeader) string {
	get := func(k string) string {
		if h == nil {
			return ""
		}
		return strings.TrimSpace(h.Get(k))
	}
	if cfray := get("Cf-Ray"); cfray != "" {
		parts := strings.Split(cfray, "-")
		tail := strings.ToUpper(strings.TrimSpace(parts[len(parts)-1]))
		if len(tail) == 3 && isAlpha(tail) {
			return tail
		}
	}
	if pop := get("X-Amz-Cf-Pop"); pop != "" {
		if len(pop) >= 3 {
			return strings.ToUpper(pop[:3])
		}
		return strings.ToUpper(pop)
	}
	server := strings.ToLower(get("Server"))
	if strings.Contains(server, "bunnycdn") {
		if i := strings.Index(server, "-"); i >= 0 && i+2 < len(server) {
			return strings.ToUpper(server[i+1 : i+3])
		}
		return ""
	}
	if x77 := get("X-77-Pop"); x77 != "" {
		if len(x77) >= 2 {
			return strings.ToUpper(x77[len(x77)-2:])
		}
	}
	if served := get("X-Served-By"); served != "" {
		segs := strings.Split(served, ",")
		last := segs[len(segs)-1]
		fields := strings.Split(last, "-")
		var hit string
		for _, p := range fields {
			if len(p) == 3 && isAlpha(p) {
				hit = p
			}
		}
		if hit != "" {
			return strings.ToUpper(hit)
		}
	}
	return ""
}

func isAlpha(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

// httpConn 一个「连 ip、但 Host/SNI 用目标域名」的连接。
type httpConn struct {
	conn net.Conn
	br   *bufio.Reader
	host string
}

// openHTTP 建立到指定 IP 的连接（TLS 时 SNI 用目标域名）。
func openHTTP(ip string, pu ParsedURL, timeout time.Duration) (*httpConn, error) {
	c, err := dialTCP(ip, pu.Port, timeout)
	if err != nil {
		return nil, err
	}
	if pu.Scheme == "http" {
		return &httpConn{conn: c, br: bufio.NewReaderSize(c, 32*1024), host: pu.Host}, nil
	}
	c.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(c, TLSConfig(pu.Host))
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return &httpConn{conn: tc, br: bufio.NewReaderSize(tc, 32*1024), host: pu.Host}, nil
}

func (h *httpConn) writeHead(method string, pu ParsedURL, extra ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, pu.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", pu.Host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", UA)
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Accept-Encoding: identity\r\n")
	for i := 0; i+1 < len(extra); i += 2 {
		fmt.Fprintf(&b, "%s: %s\r\n", extra[i], extra[i+1])
	}
	b.WriteString("Connection: close\r\n\r\n")
	_, err := h.conn.Write([]byte(b.String()))
	return err
}

func (h *httpConn) readHead() (int, *textproto.MIMEHeader, error) {
	tp := textproto.NewReader(h.br)
	line, err := tp.ReadLine()
	if err != nil {
		return 0, nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("bad status line: %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("bad status code: %q", parts[1])
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return status, nil, err
	}
	return status, &hdr, nil
}

// HTTPHead 单次 HEAD 请求。返回 (rtt_ms, colo, status, err)。
func HTTPHead(ip string, pu ParsedURL, timeout time.Duration) (float64, string, int, error) {
	if pu.Host == "" {
		return 0, "", 0, fmt.Errorf("测速地址缺少主机名")
	}
	c, err := openHTTP(ip, pu, timeout)
	if err != nil {
		return 0, "", 0, err
	}
	defer c.conn.Close()
	c.conn.SetDeadline(time.Now().Add(timeout))

	t0 := time.Now()
	if err := c.writeHead("HEAD", pu); err != nil {
		return 0, "", 0, err
	}
	status, hdr, err := c.readHead()
	rtt := float64(time.Since(t0).Microseconds()) / 1000.0
	if err != nil && hdr == nil {
		return 0, "", 0, err
	}
	return rtt, ParseColo(hdr), status, nil
}

// DownloadRound 下载一轮，返回 (字节/秒, colo)。
// 速度取「首字节 → 窗口结束」区间；失败返回 (0,"",false)。
//
// 合理性校验（踩过的坑）：
//   - 阈值刻意放低（32KB / 0.4s）：慢节点也是有效样本，砍太狠会把真实但
//     带宽只有几十 KB/s 的节点全判成失败。
//   - 超过 150MB/s 视为异常（千兆口跑不出来），否则「响应只有几 KB、
//     连接立刻 EOF」时会算出 4.5GB/s 这种荒谬速度。
func DownloadRound(ip string, pu ParsedURL, window time.Duration, timeout time.Duration) (float64, string, bool) {
	if pu.Host == "" {
		return 0, "", false
	}
	c, err := openHTTP(ip, pu, timeout)
	if err != nil {
		return 0, "", false
	}
	defer c.conn.Close()

	extra := []string{}
	if IsCFSpeedHost(pu.Host) {
		// speed.cloudflare.com/__down 对不带 Referer 的非浏览器客户端一律回 403
		extra = append(extra,
			"Referer", fmt.Sprintf("%s://%s/", pu.Scheme, pu.Host),
			"Origin", fmt.Sprintf("%s://%s", pu.Scheme, pu.Host))
	}
	// 单轮硬上限：窗口 + 5s，防止某轮卡死拖垮整轮测速
	hardDeadline := time.Now().Add(window + 5*time.Second)
	c.conn.SetReadDeadline(hardDeadline)
	if err := c.writeHead("GET", pu, extra...); err != nil {
		return 0, "", false
	}
	status, hdr, err := c.readHead()
	if hdr == nil && err != nil {
		return 0, "", false
	}
	colo := ParseColo(hdr)
	if status != 200 {
		return 0, colo, false
	}

	buf := make([]byte, Chunk)
	var firstAt time.Time
	var loaded int64
	for {
		c.conn.SetReadDeadline(hardDeadline)
		n, rerr := c.br.Read(buf)
		if n > 0 {
			now := time.Now()
			if firstAt.IsZero() {
				firstAt = now
			}
			loaded += int64(n)
			if now.Sub(firstAt) >= window {
				break
			}
		}
		if rerr != nil {
			break
		}
		if now := time.Now(); now.After(hardDeadline) {
			break
		}
	}
	if firstAt.IsZero() || loaded == 0 {
		return 0, colo, false
	}
	elapsed := time.Since(firstAt).Seconds()
	if elapsed < 0.40 || loaded < 32*1024 {
		return 0, colo, false
	}
	bps := float64(loaded) / elapsed
	if bps > 150*1024*1024 {
		return 0, colo, false
	}
	return bps, colo, true
}

// ProbeAlive 判断某个 IP 现在是否还活着。返回 (ok, rtt_ms, colo, err)。
//
// 与测速阶段用同一套「真实往返」口径，避免被本地 SYN 伪造骗过：
//   - tls      TLS 握手必须走到对端
//   - httping  HEAD 请求必须拿到响应
//   - ping     connect 成功本身不可信，追加一次 TLS 校验
func ProbeAlive(ip string, mode string, port int, testURL string, timeout time.Duration) (bool, float64, string, string) {
	pu := ParseTestURL(testURL, port)
	switch strings.ToLower(mode) {
	case "httping":
		rtt, colo, status, err := HTTPHead(ip, pu, timeout)
		if err != nil {
			return false, 0, "", err.Error()
		}
		ok := status >= 200 && status < 400
		if !ok {
			return false, 0, colo, fmt.Sprintf("HTTP %d", status)
		}
		return true, rtt, colo, ""
	case "ping":
		ms, ok := TCPRTT(ip, port, timeout)
		if !ok {
			return false, 0, "", "TCP 建连失败"
		}
		if _, ok2 := TLSRTT(ip, port, pu.Host, timeout); !ok2 {
			return false, 0, "", "连接被本地伪造（TLS 无法到达对端）"
		}
		return true, ms, "", ""
	default:
		ms, ok := TLSRTT(ip, port, pu.Host, timeout)
		if !ok {
			return false, 0, "", "TLS 握手失败"
		}
		return true, ms, "", ""
	}
}
