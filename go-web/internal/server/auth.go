package server

// 鉴权与安全门禁。
//
// 两件事，互相独立：
//
// 一、来源网段门禁（对应原应用 cf-dns-select 的 DSA_ALLOWED_CIDRS）
//     只放行指定 CIDR 的请求进来。原应用的做法是「没配就拒绝启动」，
//     因为它把 Dashboard 暴露在 0.0.0.0 上，而 Dashboard 里存着 AdGuard 凭据。
//     本应用的默认监听地址是 127.0.0.1（由 fnOS 通过 CGI 反代），
//     外部根本连不上，所以默认**不设门禁**；一旦用户把它绑到 0.0.0.0，
//     就必须显式配 CFIP_ALLOWED_CIDRS，否则拒绝启动——和原应用同样的思路：
//     宁可起不来，也不要裸奔。
//
// 二、身份认证（两种方式并存）
//     - Cookie 会话（源自原应用 /api/login）：POST /api/login 拿 token，
//       之后带 Cookie。适合浏览器访问 Dashboard。
//     - Basic Auth：适合 curl / 脚本 / 内网工具。
//     两种都校验同一个口令（config.password）。没设口令时全部放行。

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "cfip_token"
	sessionTTL    = 12 * time.Hour
)

// sessionStore 进程内的会话表。
//
// 为什么不签名 token 而用内存表：本应用是单进程、单用户、无集群，
// 内存表足够且能立刻吊销（重启即全部失效）。签名方案反而要额外管理密钥。
type sessionStore struct {
	mu sync.Mutex
	m  map[string]time.Time // token -> 过期时间
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]time.Time)}
}

func (s *sessionStore) issue() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// 熵源不可用时退回时间戳，宁可弱一点也不让登录彻底不可用
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺手清理过期会话，避免无限增长
	now := time.Now()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
	s.m[tok] = now.Add(sessionTTL)
	return tok
}

func (s *sessionStore) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

func (s *sessionStore) revoke(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

// ---------------------------------------------------------------- 门禁

// CIDRGate 来源网段门禁。nil 表示不限制。
type CIDRGate struct {
	nets  []*net.IPNet
	empty bool // 配了但一个都没解析成功
}

// ParseCIDRGate 解析逗号分隔的 CIDR 列表。空字符串或通配符（*、all、any）返回 nil（不限制）。
//
// 同时接受纯 IP（自动补成 /32 或 /128），方便用户直接写 "192.168.1.12"。
func ParseCIDRGate(spec string) *CIDRGate {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" || strings.EqualFold(spec, "all") || strings.EqualFold(spec, "any") {
		return nil
	}
	g := &CIDRGate{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				if ip.To4() != nil {
					part += "/32"
				} else {
					part += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			continue
		}
		g.nets = append(g.nets, n)
	}
	if len(g.nets) == 0 {
		g.empty = true
	}
	return g
}

// Allow 判断来源是否放行。环回地址永远放行——本机健康检查、以及飞牛
// CGI 网关经 Unix 套接字转发进来的请求都靠这条规则。
//
// 注意 Unix 套接字连接的 RemoteAddr 是 "@"，net.SplitHostPort 解析不出主机，
// 于是 host 保持原值 "@"，ParseIP 返回 nil。这种情况按环回处理：
// 能连上 Unix 套接字本身就说明来源在本机，比任何 IP 判断都可靠。
func (g *CIDRGate) Allow(remoteAddr string) bool {
	if g == nil {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if host == "@" || host == "" {
		// Unix 域套接字连接，来源是本机进程
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if g.empty {
		// 配了但全都解析失败：安全起见一律拒绝，而不是静默放行
		return false
	}
	for _, n := range g.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- 认证

// needsAuth 是否需要口令（未设口令视为不需要）。
func (a *App) needsAuth() string {
	return strings.TrimSpace(a.Store.Load().Password)
}

// checkPassword 常数时间比对，避免时序侧信道。
func checkPassword(given, want string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// authed 判断请求是否已通过认证（Cookie 或 Basic Auth 任一即可）。
func (a *App) authed(r *http.Request) bool {
	pwd := a.needsAuth()
	if pwd == "" {
		return true
	}
	// ① Cookie 会话
	if c, err := r.Cookie(sessionCookie); err == nil && a.sessions.valid(c.Value) {
		return true
	}
	// ② Basic Auth
	if _, given, ok := r.BasicAuth(); ok && checkPassword(given, pwd) {
		return true
	}
	// ③ Authorization: Bearer <token>（方便脚本调用，与原应用 token 语义一致）
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if a.sessions.valid(strings.TrimPrefix(h, "Bearer ")) {
			return true
		}
	}
	return false
}
