// Package adguard —— AdGuard Home 重写表同步。
//
// 语义与原应用（cf-dns-select）完全一致：
//   - 接管整张重写表：同步时把实例的 DNS 重写收敛为「期望集合」，
//     即清掉不在期望集合里的记录，再补齐缺失记录（非全清重发，避免瞬间断解析）；
//     期望之外的旧记录（包括别的工具写的）会被清掉。
//   - want: domain -> answer 集合；空集合表示该域名应无任何记录。
package adguard

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"cfip-opt/internal/engine"
)

// APIError 带 HTTP 状态码的错误。4xx 不重试（凭据/参数问题）。
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("adguard %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, truncate(e.Body, 200))
}

func (e *APIError) ClientError() bool { return e.Status >= 400 && e.Status < 500 }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Rewrite 一条 DNS 重写记录。
type Rewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled bool   `json:"enabled"`
}

// Client AdGuard Home API 客户端。
type Client struct {
	BaseURL  string
	Username string
	Password string
	HTTP     *http.Client
}

// NewClient 构造客户端；URL 未带 scheme 时补 http://。
func NewClient(rawURL, username, password string) *Client {
	u := strings.TrimSpace(strings.TrimRight(rawURL, "/"))
	if u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}
	return &Client{
		BaseURL:  u,
		Username: username,
		Password: password,
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// AdGuard 常部署在局域网自签证书上，跳过校验以避免同步直接失败
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           nil,
			},
		},
	}
}

func (c *Client) do(method, path string, body any) (json.RawMessage, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Username != "" || c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: string(raw)}
	}
	return raw, nil
}

func (c *Client) retry(method, path string, body any, attempts int) (json.RawMessage, error) {
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			backoff := time.Duration(1<<uint(i-1)) * time.Second
			if backoff > 4*time.Second {
				backoff = 4 * time.Second
			}
			time.Sleep(backoff)
		}
		raw, err := c.do(method, path, body)
		if err == nil {
			return raw, nil
		}
		if ae, ok := err.(*APIError); ok && ae.ClientError() {
			return nil, err
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("adguard %s %s: 全部重试失败", method, path)
	}
	return nil, last
}

// ListRewrites 列出全部重写记录。
func (c *Client) ListRewrites() ([]Rewrite, error) {
	raw, err := c.retry("GET", "/control/rewrite/list", nil, 3)
	if err != nil {
		return nil, err
	}
	var arr []struct {
		Domain  string `json:"domain"`
		Answer  string `json:"answer"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, err
	}
	out := make([]Rewrite, 0, len(arr))
	for _, e := range arr {
		en := true
		if e.Enabled != nil {
			en = *e.Enabled
		}
		out = append(out, Rewrite{Domain: e.Domain, Answer: e.Answer, Enabled: en})
	}
	return out, nil
}

func (c *Client) add(domain, answer string) error {
	_, err := c.retry("POST", "/control/rewrite/add", map[string]any{
		"domain": domain, "answer": answer, "enabled": true,
	}, 3)
	return err
}

func (c *Client) del(domain, answer string) error {
	_, err := c.retry("POST", "/control/rewrite/delete", map[string]any{
		"domain": domain, "answer": answer, "enabled": true,
	}, 3)
	return err
}

// Test 测试连通性。
func (c *Client) Test() error {
	_, err := c.retry("GET", "/control/rewrite/list", nil, 1)
	return err
}

// Stats 一次收敛的统计。
type Stats struct {
	Written int `json:"written"`
	Removed int `json:"removed"`
}

// ReplaceRewrites 把重写表收敛到 want。
func (c *Client) ReplaceRewrites(want map[string]map[string]struct{}) (Stats, error) {
	var stats Stats
	current, err := c.ListRewrites()
	if err != nil {
		return stats, err
	}
	// 深拷贝，避免边删边改原集合
	pending := make(map[string]map[string]struct{}, len(want))
	for d, as := range want {
		cp := make(map[string]struct{}, len(as))
		for a := range as {
			cp[a] = struct{}{}
		}
		pending[d] = cp
	}

	// 1) 删除期望之外 / 不再需要的记录
	for _, e := range current {
		answers, ok := pending[e.Domain]
		if !ok {
			if err := c.del(e.Domain, e.Answer); err != nil {
				return stats, err
			}
			stats.Removed++
			continue
		}
		if _, need := answers[e.Answer]; !need {
			if err := c.del(e.Domain, e.Answer); err != nil {
				return stats, err
			}
			stats.Removed++
			continue
		}
		delete(answers, e.Answer) // 已存在，不用重写
	}

	// 2) 补齐缺失记录
	domains := make([]string, 0, len(pending))
	for d := range pending {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	for _, d := range domains {
		answers := pending[d]
		ans := make([]string, 0, len(answers))
		for a := range answers {
			ans = append(ans, a)
		}
		sort.Strings(ans)
		for _, a := range ans {
			if err := c.add(d, a); err != nil {
				return stats, err
			}
			stats.Written++
		}
	}
	return stats, nil
}

// BuildWant 构造期望重写集合（与原应用 buildWant 一致）：
//   - 每个域名写 bestIP；
//   - wildcard 域名同时写「裸域名 + *.域名」两条；
//   - 非 wildcard 域名把 *.域名 置为空集（收敛语义会清掉残留通配记录）；
//   - manual 追加进去（与最优 IP 重写并存）。
//
// bestIP 为空时不产生最优 IP 记录，只保留手动重写。
func BuildWant(domains []engine.DNSDomain, bestIP string, manual []engine.ManualRewrite) map[string]map[string]struct{} {
	want := make(map[string]map[string]struct{}, len(domains)*2)
	if bestIP != "" {
		for _, d := range domains {
			name := strings.TrimSpace(d.Domain)
			if name == "" {
				continue
			}
			want[name] = map[string]struct{}{bestIP: {}}
			if d.Wildcard {
				want["*."+name] = map[string]struct{}{bestIP: {}}
			} else {
				want["*."+name] = map[string]struct{}{}
			}
		}
	}
	for _, m := range manual {
		dom := strings.TrimSpace(m.Domain)
		ans := strings.TrimSpace(m.Answer)
		if dom == "" || ans == "" {
			continue
		}
		if want[dom] == nil {
			want[dom] = make(map[string]struct{}, 1)
		}
		want[dom][ans] = struct{}{}
	}
	return want
}

// InstanceResult 单个实例的同步结果。
type InstanceResult struct {
	OK    bool   `json:"ok"`
	Stats *Stats `json:"stats,omitempty"`
	Error string `json:"error,omitempty"`
	// Drift 同步后复查出的残留差异（正常情况下应为空）。
	// 非空说明收敛没做干净——通常是实例上有别的进程在同时改重写表。
	Drift []DriftItem `json:"drift,omitempty"`
}

// DriftItem 一条漂移记录：目标值该有却没有，或旧值该删却没删。
type DriftItem struct {
	Domain string `json:"domain"`
	Want   string `json:"want"`  // 目标应指向的 IP
	Now    string `json:"now"`   // 当前实际指向的 IP（缺失时为空）
	Kind   string `json:"kind"`  // "missing" 缺少 | "stale" 过期
}

// ComputeDrift 对比当前重写表与期望集合，返回漂移列表。**只读，不修改实例**。
//
// 判定口径与原应用 cf-dns-select 的 drift 一致：
//   - missing：目标域名应该指向 wantIP，但表里没有这条记录；
//   - stale  ：表里存在指向非 wantIP 的记录（旧 IP 残留），或该域名本该无记录却有记录。
//
// 为什么单独做漂移检测而不只看同步结果：同步是「先删后加」，如果中途失败或
// 有并发写入，Stats 会显示成功但表里仍不一致。漂移检测是同步后的对账，
// 也是 UI 上「实例是否真的生效」的唯一可信依据。
func ComputeDrift(current []Rewrite, want map[string]map[string]struct{}, desiredIP string) []DriftItem {
	// 建立 域名 → 现有 answer 集合
	have := make(map[string]map[string]struct{}, len(current))
	for _, e := range current {
		if have[e.Domain] == nil {
			have[e.Domain] = make(map[string]struct{}, 2)
		}
		have[e.Domain][e.Answer] = struct{}{}
	}

	var out []DriftItem
	seen := make(map[string]struct{}, len(current)*2) // 去重：同一 domain+now 只报一次
	emit := func(it DriftItem) {
		k := it.Domain + "\x00" + it.Now
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, it)
	}

	for domain, answers := range want {
		// 该域名本该无任何记录（非 wildcard 的 *. 占位）
		if len(answers) == 0 {
			for ans := range have[domain] {
				emit(DriftItem{Domain: domain, Want: "", Now: ans, Kind: "stale"})
			}
			continue
		}
		// 该域名本该指向特定 IP 集合
		for wantAns := range answers {
			if _, ok := have[domain][wantAns]; ok {
				continue
			}
			// 缺这条：把现状记进 Now 便于定位（可能是旧 IP，也可能完全没记录）
			now := ""
			for a := range have[domain] {
				now = a
				break
			}
			kind := "missing"
			if now != "" && now != wantAns {
				kind = "stale"
			}
			emit(DriftItem{Domain: domain, Want: wantAns, Now: now, Kind: kind})
		}
		// 存在多余的旧答案（指向别的 IP）
		for haveAns := range have[domain] {
			if _, ok := answers[haveAns]; !ok {
				emit(DriftItem{Domain: domain, Want: strings.TrimSpace(firstKey(answers)), Now: haveAns, Kind: "stale"})
			}
		}
	}
	// 期望集合里完全没提到的域名也算残留（整表接管语义）
	for domain, ansSet := range have {
		if _, ok := want[domain]; ok {
			continue
		}
		for ans := range ansSet {
			emit(DriftItem{Domain: domain, Want: "", Now: ans, Kind: "stale"})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Now < out[j].Now
	})
	return out
}

// firstKey 取集合里唯一的元素（期望集合通常只有 1 个答案）。
func firstKey(m map[string]struct{}) string {
	for k := range m {
		return k
	}
	return ""
}

// Inspect 只读检查单个实例的漂移，不写入任何东西。
func (c *Client) Inspect(want map[string]map[string]struct{}, desiredIP string) ([]DriftItem, error) {
	current, err := c.ListRewrites()
	if err != nil {
		return nil, err
	}
	return ComputeDrift(current, want, desiredIP), nil
}

// SyncInstances 把 bestIP 同步到全部实例。
func SyncInstances(dns engine.DNS, bestIP string, log func(string)) map[string]InstanceResult {
	want := BuildWant(dns.Domains, bestIP, dns.ManualRewrites)
	out := make(map[string]InstanceResult, len(dns.Instances))
	for _, inst := range dns.Instances {
		name := inst.Name
		if name == "" {
			name = inst.URL
		}
		if name == "" {
			name = "未命名"
		}
		c := NewClient(inst.URL, inst.Username, inst.Password)
		stats, err := c.ReplaceRewrites(want)
		if err != nil {
			out[name] = InstanceResult{OK: false, Error: err.Error()}
			if log != nil {
				log(fmt.Sprintf("DNS 同步 [%s] 失败：%v", name, err))
			}
			continue
		}
		// 同步后立刻对账，把没收敛干净的差异报出来
		drift, derr := c.Inspect(want, bestIP)
		if derr != nil {
			drift = nil // 对账失败不影响同步结果，只是没有 drift 信息
		}
		out[name] = InstanceResult{OK: true, Stats: &stats, Drift: drift}
		if log != nil {
			msg := fmt.Sprintf("DNS 同步 [%s]：写入 %d 条，清理 %d 条", name, stats.Written, stats.Removed)
			if len(drift) > 0 {
				msg += fmt.Sprintf("；仍残留 %d 处差异", len(drift))
			}
			log(msg)
		}
	}
	return out
}

