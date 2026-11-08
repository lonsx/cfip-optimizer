package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Download 下载测速配置。
type Download struct {
	Enabled      bool    `json:"enabled"`
	TopN         int     `json:"top_n"`
	Rounds       int     `json:"rounds"`
	WindowSec    float64 `json:"window_sec"`
	GapMS        int     `json:"gap_ms"`
	MinSpeedKBps float64 `json:"min_speed_kbps"`
	URL          string  `json:"url"`
}

// Guard 可达性守护配置。
type Guard struct {
	Enabled         bool `json:"enabled"`
	IntervalSec     int  `json:"interval_sec"`
	ProbeTimeout    int  `json:"probe_timeout"`
	FailThreshold   int  `json:"fail_threshold"`
	AutoRerun       bool `json:"auto_rerun"`
	RerunCooldownS  int  `json:"rerun_cooldown_sec"`
	RefreshSec      int  `json:"refresh_sec"`

	// Failover 故障快速轮换：当前 IP 挂了先从上一轮结果里挑个备选切过去（秒级），
	// 备选也不可用才做整轮重测（分钟级）。默认开启。
	Failover *bool `json:"failover"`
}

// FailoverEnabled 读取故障轮换开关，缺失视为开启。
func (g Guard) FailoverEnabled() bool {
	if g.Failover == nil {
		return true
	}
	return *g.Failover
}

// DNSInstance 一个 AdGuard Home 实例。
type DNSInstance struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// DNSDomain 一个要写重写的域名。
type DNSDomain struct {
	Domain   string `json:"domain"`
	Wildcard bool   `json:"wildcard"`
}

// ManualRewrite 手动重写条目（与最优 IP 重写并存）。
type ManualRewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// DNS 同步配置。
type DNS struct {
	AutoSync        bool            `json:"auto_sync"`
	Instances       []DNSInstance   `json:"instances"`
	Domains         []DNSDomain     `json:"domains"`
	ManualRewrites  []ManualRewrite `json:"manual_rewrites"`
}

// Config 完整配置。字段名与 Python 版的 config.json 完全一致，
// 便于直接复用 NAS 上已有的配置文件，无需迁移。
type Config struct {
	Mode              string   `json:"mode"`
	Port              int      `json:"port"`
	Routines          int      `json:"routines"`
	IPFile            string   `json:"ip_file"`
	IPv6              bool     `json:"ipv6"`
	IPv6File          string   `json:"ipv6_file"`
	V6PerCIDR         int      `json:"v6_per_cidr"`
	TestAll           bool     `json:"test_all"`
	MaxPool           int      `json:"max_pool"`
	SplitByFamily     *bool    `json:"split_by_family"`
	LatencyCap        int      `json:"latency_cap"`
	LatencyRounds     int      `json:"latency_rounds"`
	WarmupDiscard     bool     `json:"warmup_discard"`
	FastFail          FlexibleInt `json:"fast_fail"`
	RoundGapMS        int      `json:"round_gap_ms"`
	TimeoutMS         int      `json:"timeout_ms"`
	MaxDelay          float64  `json:"max_delay"`
	MaxLoss           *float64 `json:"max_loss"`
	CfColo            string   `json:"cfcolo"`
	// RegionProbeUnknown 控制地区前置阶段的补探策略：
	//   false（默认）＝ 只补探「够延迟阶段用」的量，单轮秒级完成；
	//   true          ＝ 把库里没有的候选全部探一遍，最大化覆盖面但很慢。
	RegionProbeUnknown bool   `json:"region_probe_unknown"`
	KeepTop           int      `json:"keep_top"`
	TestURL           string   `json:"test_url"`
	Download          Download `json:"download"`
	Password          string   `json:"password"`
	Guard             Guard    `json:"guard"`
	DNS               DNS      `json:"dns"`

	// ---- 定时任务（字段名与原应用 cf-dns-select 的 /api/config 保持一致）----

	// IntervalMinutes 自动测速间隔（分钟）。0 表示关闭定时测速。
	IntervalMinutes int `json:"interval_minutes"`
	// RunOnStart 应用启动后立即跑一轮（不论间隔是否到点）。
	RunOnStart bool `json:"run_on_start"`
	// LastResultIP / LastResultTime 上一轮的最优 IP 与完成时间，
	// 用于重启后 UI 立即显示历史结论、以及「IP 有没有变」的比对。
	LastResultIP   string `json:"last_result_ip"`
	LastResultTime string `json:"last_result_time"`
}

// FlexibleInt 兼容旧配置：历史上 fast_fail 是布尔（true=首轮失败即退出），
// 新语义是「连续失败次数」。反序列化时统一折算成数值。
type FlexibleInt int

func (f *FlexibleInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		*f = 0
		return nil
	}
	if s == "true" {
		*f = 2
		return nil
	}
	if s == "false" {
		*f = 0
		return nil
	}
	// 可能是数字，也可能是带引号的数字
	s = strings.Trim(s, `"`)
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*f = 0
		return nil
	}
	*f = FlexibleInt(int(n))
	return nil
}

// DefaultConfig 与 Python 版 DEFAULT_CONFIG 逐项对齐。
func DefaultConfig() Config {
	t := true
	ml := 1.0
	return Config{
		Mode:               "ping",
		Port:               443,
		Routines:           64,
		IPFile:             "ip.txt",
		IPv6:               false,
		IPv6File:           "ipv6.txt",
		V6PerCIDR:          6,
		TestAll:            false,
		MaxPool:            20000,
		SplitByFamily:      &t,
		LatencyCap:         20000,
		LatencyRounds:      6,
		WarmupDiscard:      true,
		FastFail:           2,
		RoundGapMS:         120,
		TimeoutMS:          2000,
		MaxDelay:           700,
		MaxLoss:            &ml,
		CfColo:             "",
		RegionProbeUnknown: false,
		KeepTop:            20,
		TestURL:            "https://speed.cloudflare.com/",
		Download: Download{
			Enabled:      true,
			TopN:         20,
			Rounds:       3,
			WindowSec:    5,
			GapMS:        300,
			MinSpeedKBps: 0,
			URL:          "https://speed.cloudflare.com/__down?bytes=100000000",
		},
		Guard: Guard{
			Enabled:        true,
			IntervalSec:    60,
			ProbeTimeout:   6,
			FailThreshold:  2,
			AutoRerun:      true,
			RerunCooldownS: 900,
			RefreshSec:     0,
			Failover:       &t,
		},
		DNS: DNS{AutoSync: true, Instances: []DNSInstance{}, Domains: []DNSDomain{}, ManualRewrites: []ManualRewrite{}},

		// 定时测速默认关闭：新装用户先手动跑一轮确认配置正确，再开定时。
		IntervalMinutes: 0,
		RunOnStart:      false,
		LastResultIP:    "",
		LastResultTime:  "",
	}
}

// SplitEnabled 读取「按地址族对半分」开关。显式 null / 缺失都视为默认开启。
func (c Config) SplitEnabled() bool {
	if c.SplitByFamily == nil {
		return true
	}
	return *c.SplitByFamily
}

// LossLimit 丢包上限，缺失时视为 1.0（允许全部丢弃）。
func (c Config) LossLimit() float64 {
	if c.MaxLoss == nil {
		return 1.0
	}
	return *c.MaxLoss
}

// Timeout 探测超时（毫秒数值）。
func (c Config) Timeout() float64 { return float64(c.TimeoutMS) }

// TimeoutDurMS 探测超时（毫秒整数，下限 200ms）。
func (c Config) TimeoutDurMS() int {
	if c.TimeoutMS < 200 {
		return 200
	}
	return c.TimeoutMS
}

// ConfigStore 配置文件读写（原子替换）。
type ConfigStore struct {
	Path string
	mu   sync.Mutex

	// 调度时间戳单独存一个文件，避免每次跑任务都重写 config.json
	// （config.json 是用户可编辑的，频繁写会有冲突风险）
	schedPath string
}

func NewConfigStore(dataDir string) *ConfigStore {
	return &ConfigStore{
		Path:      filepath.Join(dataDir, "config.json"),
		schedPath: filepath.Join(dataDir, "sched.json"),
	}
}

// schedState 定时任务的持久化状态。
type schedState struct {
	LastRunAt string `json:"last_run_at"`
}

// MarkScheduled 记录「刚刚触发过一次定时任务」。
func (s *ConfigStore) MarkScheduled() {
	b, _ := json.Marshal(schedState{LastRunAt: time.Now().Format(time.RFC3339)})
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp := s.schedPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, s.schedPath)
}

// LastScheduledAt 上次定时触发的时刻（零值表示从未触发）。
func (s *ConfigStore) LastScheduledAt() time.Time {
	s.mu.Lock()
	raw, err := os.ReadFile(s.schedPath)
	s.mu.Unlock()
	if err != nil {
		return time.Time{}
	}
	var st schedState
	if json.Unmarshal(raw, &st) != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, st.LastRunAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// NextRunAt 下一次该触发的时刻 = 上次触发 + 间隔（从未触发过则视为「现在就该跑」）。
func (s *ConfigStore) NextRunAt(interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	last := s.LastScheduledAt()
	if last.IsZero() {
		return time.Now()
	}
	return last.Add(interval)
}

// Load 读取配置；文件缺失或损坏时返回默认值。
// 老配置里可能有新版本已删除的键、或 fast_fail 是布尔，都能安全兼容。
func (s *ConfigStore) Load() Config {
	cfg := DefaultConfig()
	s.mu.Lock()
	raw, err := os.ReadFile(s.Path)
	s.mu.Unlock()
	if err != nil {
		return cfg
	}
	// 先合并到默认值上（JSON 未出现的字段保留默认）
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return DefaultConfig()
	}
	return normalize(cfg)
}

// normalize 补齐零值、纠正非法组合。
func normalize(c Config) Config {
	if c.Routines < 1 {
		c.Routines = 64
	}
	if c.Routines > 512 {
		c.Routines = 512
	}
	if c.Port <= 0 || c.Port > 65535 {
		c.Port = 443
	}
	if c.LatencyRounds < 1 {
		c.LatencyRounds = 1
	}
	if c.Download.TopN < 1 {
		c.Download.TopN = 1
	}
	if c.Download.Rounds < 1 {
		c.Download.Rounds = 1
	}
	if c.Download.WindowSec < 1 {
		c.Download.WindowSec = 1
	}
	if c.MaxPool <= 0 {
		c.MaxPool = 20000
	}
	if c.KeepTop < 1 {
		c.KeepTop = 20
	}
	if c.V6PerCIDR < 1 {
		c.V6PerCIDR = 1
	}
	if c.IPFile == "" {
		c.IPFile = "ip.txt"
	}
	if c.IPv6File == "" {
		c.IPv6File = "ipv6.txt"
	}
	if c.TestURL == "" {
		c.TestURL = "https://speed.cloudflare.com/"
	}
	if c.Mode == "" {
		c.Mode = "ping"
	}
	if c.Guard.IntervalSec < 15 {
		c.Guard.IntervalSec = 60
	}
	if c.Guard.ProbeTimeout < 1 {
		c.Guard.ProbeTimeout = 6
	}
	if c.Guard.FailThreshold < 1 {
		c.Guard.FailThreshold = 2
	}
	if c.DNS.Instances == nil {
		c.DNS.Instances = []DNSInstance{}
	}
	if c.DNS.Domains == nil {
		c.DNS.Domains = []DNSDomain{}
	}
	if c.DNS.ManualRewrites == nil {
		c.DNS.ManualRewrites = []ManualRewrite{}
	}
	return c
}

// Save 原子写入配置。
func (s *ConfigStore) Save(c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Merge 只覆盖 incoming 中出现的字段，避免前端局部提交把别的参数冲掉。
//
// 兼容两种 body 形态：
//   扁平   {"mode":"tls","latency_rounds":4}
//   包裹   {"config":{"mode":"tls","latency_rounds":4}}
// 早先只支持扁平，脚本按 GET 的返回结构（{"config":{...}}）原样回提交时，
// 整包被当成"未知字段"静默丢弃，接口仍回 200 + 当前配置，看起来像"写成功了
// 但没生效"——排查成本极高。现在两种都吃，且静默丢弃的问题一并堵住。
func (s *ConfigStore) Merge(incoming map[string]json.RawMessage) (Config, error) {
	// 展开 config 包裹层（深一层即可，不递归）
	if inner, ok := incoming["config"]; ok && len(inner) > 0 && inner[0] == '{' {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(inner, &nested); err == nil {
			delete(incoming, "config")
			for k, v := range nested {
				if _, dup := incoming[k]; !dup {
					incoming[k] = v
				}
			}
		}
	}
	cfg := s.Load()
	// 借助 marshal 往返做字段级合并：先把当前配置转成 map，再用 incoming 覆盖，
	// 最后反序列化回来。这样新增字段自动被支持，无需逐个列举。
	cur, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(cur, &m); err != nil {
		return cfg, err
	}
	// applied 记录真正被认出的字段数；unknown 收集没认出的键，便于报错时点名
	applied := 0
	var unknown []string
	for k, v := range incoming {
		if k == "dns" {
			// dns 段做浅合并，保留未提交的子字段（尤其是密码）
			var curDNS, newDNS map[string]json.RawMessage
			_ = json.Unmarshal(m["dns"], &curDNS)
			if curDNS == nil {
				curDNS = map[string]json.RawMessage{}
			}
			if err := json.Unmarshal(v, &newDNS); err == nil {
				for dk, dv := range newDNS {
					curDNS[dk] = dv
				}
				merged, _ := json.Marshal(curDNS)
				m["dns"] = merged
				applied++
			}
			continue
		}
		if k == "download" {
			var curDL, newDL map[string]json.RawMessage
			_ = json.Unmarshal(m["download"], &curDL)
			if curDL == nil {
				curDL = map[string]json.RawMessage{}
			}
			if err := json.Unmarshal(v, &newDL); err == nil {
				for dk, dv := range newDL {
					curDL[dk] = dv
				}
				merged, _ := json.Marshal(curDL)
				m["download"] = merged
				applied++
			}
			continue
		}
		if k == "guard" {
			var curG, newG map[string]json.RawMessage
			_ = json.Unmarshal(m["guard"], &curG)
			if curG == nil {
				curG = map[string]json.RawMessage{}
			}
			if err := json.Unmarshal(v, &newG); err == nil {
				for gk, gv := range newG {
					curG[gk] = gv
				}
				merged, _ := json.Marshal(curG)
				m["guard"] = merged
				applied++
			}
			continue
		}
		if _, exists := m[k]; exists {
			m[k] = v
			applied++
		} else {
			unknown = append(unknown, k)
		}
	}
	// 一个字段都没认出来，说明调用方传的结构不对（例如套了一层未知的包裹）。
	// 这时必须报错——静默返回 200 会让调用方以为写成功了。
	if applied == 0 && len(incoming) > 0 {
		sort.Strings(unknown)
		return cfg, fmt.Errorf("没有可识别的配置字段，未做任何修改（收到 %d 个字段：%s）",
			len(incoming), strings.Join(unknown, ", "))
	}
	merged, err := json.Marshal(m)
	if err != nil {
		return cfg, err
	}
	var out Config
	if err := json.Unmarshal(merged, &out); err != nil {
		return cfg, err
	}
	out = normalize(out)
	return out, s.Save(out)
}
