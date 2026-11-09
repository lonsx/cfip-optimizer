// Package server —— HTTP API + 单页界面 + 可达性守护。
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfip-opt/internal/adguard"
	"cfip-opt/internal/engine"
)

//go:embed assets/index.html
var assets embed.FS

// CommonColos 常用机场代码（前端下拉用）。
var CommonColos = [][2]string{
	{"HKG", "中国香港"}, {"TPE", "中国台湾"}, {"NRT", "日本东京"}, {"KIX", "日本大阪"},
	{"ICN", "韩国首尔"}, {"SIN", "新加坡"}, {"SJC", "美国圣何塞"}, {"LAX", "美国洛杉矶"},
	{"SEA", "美国西雅图"}, {"DFW", "美国达拉斯"}, {"IAD", "美国华盛顿"}, {"ORD", "美国芝加哥"},
	{"FRA", "德国法兰克福"}, {"AMS", "荷兰阿姆斯特丹"}, {"LHR", "英国伦敦"}, {"CDG", "法国巴黎"},
	{"SYD", "澳大利亚悉尼"}, {"BOM", "印度孟买"}, {"DXB", "阿联酋迪拜"}, {"BKK", "泰国曼谷"},
}

const (
	maxLog     = 400
	guardHist  = 60
	maxHistory = 30
)

// HistoryItem 每次测速的持久化归档记录。
type HistoryItem struct {
	ID        string           `json:"id"`
	Time      string           `json:"time"`
	Reason    string           `json:"reason"`
	DurationS float64          `json:"duration_s"`
	Count     int              `json:"count"`
	BestIP    string           `json:"best_ip"`
	BestColo  string           `json:"best_colo"`
	BestDelay float64          `json:"best_delay"`
	BestSpeed float64          `json:"best_speed"`
	Results   []*engine.Result `json:"results,omitempty"`
}

// ---------------------------------------------------------------- 守护状态

// GuardTick 一次守护探测记录。
type GuardTick struct {
	T   string   `json:"t"`
	OK  bool     `json:"ok"`
	RTT *float64 `json:"rtt"`
	Err string   `json:"err"`
}

// GuardState 可达性守护状态。
type GuardState struct {
	Enabled    bool        `json:"enabled"`
	WatchIP    string      `json:"watch_ip"`
	OK         *bool       `json:"ok"`
	RTTMS      *float64    `json:"rtt_ms"`
	Fails      int         `json:"fails"`
	Checks     int         `json:"checks"`
	FailTotal  int         `json:"fail_total"`
	LastCheck  string      `json:"last_check"`
	LastOK     string      `json:"last_ok"`
	LastError  string      `json:"last_error"`
	LastRerun  string      `json:"last_rerun"`
	RerunCount int         `json:"rerun_count"`
	NextCheck  string      `json:"next_check"`
	History    []GuardTick `json:"history"`
}

// DNSState DNS 同步状态。
type DNSState struct {
	LastIP    string                          `json:"last_ip"`
	LastSync  string                          `json:"last_sync"`
	Auto      *bool                           `json:"auto"`
	Instances map[string]adguard.InstanceResult `json:"instances"`
}

// ---------------------------------------------------------------- 应用

// App 全局应用状态。
type App struct {
	mu      sync.Mutex
	Store   *engine.ConfigStore
	DataDir string

	Running    bool
	Progress   engine.Progress
	Logs       []string
	Results    []*engine.Result
	Error      string
	StartedAt  string
	FinishedAt string

	NetCheck engine.NetCheck
	IPv6Info map[string]any
	DNSState DNSState
	Guard    GuardState
	History  []HistoryItem

	runner    *engine.Runner
	guardStop chan struct{}
	guardWake chan struct{}
	guardOnce sync.Once

	schedStop chan struct{}
	schedOnce sync.Once

	rerunGuard sync.Mutex // 串行化「守护触发重测」的判定

	// 故障轮换状态：记录已经确认不可达的 IP，避免在它们之间反复横跳
	failoverMu sync.Mutex
	failedIPs  map[string]struct{}

	sessions *sessionStore
	gate     *CIDRGate
}

// New 构造 App。
func New(dataDir string) *App {
	return NewWithGate(dataDir, "")
}

// NewWithGate 构造 App 并设置来源网段门禁（spec 为空表示不限制）。
func NewWithGate(dataDir, cidrs string) *App {
	a := &App{
		Store:     engine.NewConfigStore(dataDir),
		DataDir:   dataDir,
		Progress:  engine.Progress{Stage: "idle", Label: "空闲"},
		IPv6Info:  map[string]any{"ok": false, "reason": "", "checked": false},
		DNSState:  DNSState{Instances: map[string]adguard.InstanceResult{}},
		Guard:     GuardState{History: []GuardTick{}},
		guardWake: make(chan struct{}, 1),
		schedStop: make(chan struct{}),
		sessions:  newSessionStore(),
		gate:      ParseCIDRGate(cidrs),
	}
	a.restoreLast()
	a.startGuard()
	a.startScheduler()
	return a
}

func (a *App) log(msg string) {
	stamp := time.Now().Format("15:04:05")
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Logs = append(a.Logs, "["+stamp+"] "+msg)
	if len(a.Logs) > maxLog {
		a.Logs = a.Logs[len(a.Logs)-maxLog:]
	}
}

func (a *App) logSep(title string) {
	line := strings.Repeat("─", 46)
	if title != "" {
		line += " " + title
	}
	a.log(line)
}

// ---------------------------------------------------------------- 快照

// Snapshot /api/state 返回体。字段名与前端严格一致。
type Snapshot struct {
	Running     bool              `json:"running"`
	Progress    engine.Progress   `json:"progress"`
	Log         []string          `json:"log"`
	Results     []*engine.Result  `json:"results"`
	Error       string            `json:"error"`
	StartedAt   string            `json:"started_at"`
	FinishedAt  string            `json:"finished_at"`
	CfgSnapshot map[string]any    `json:"cfg_snapshot"`
	NetCheck    engine.NetCheck   `json:"netcheck"`
	IPv6Info    map[string]any    `json:"ipv6_info"`
	DNSState    DNSState          `json:"dns_state"`
	Guard        GuardState        `json:"guard"`
	Sched        SchedInfo         `json:"sched"`
	HistoryCount int               `json:"history_count"`
}

func (a *App) snapshot(cfg engine.Config) Snapshot {
	// schedInfo 会读 sched.json，放在锁外算，避免持锁做文件 IO
	sched := a.schedInfo(cfg)

	a.mu.Lock()
	defer a.mu.Unlock()
	hCount := len(a.History)
	start := len(a.Logs) - 120
	if start < 0 {
		start = 0
	}
	logs := append([]string{}, a.Logs[start:]...)
	results := a.Results
	if results == nil {
		results = []*engine.Result{}
	}
	guard := a.Guard
	guard.History = append([]GuardTick{}, a.Guard.History...)
	return Snapshot{
		Running:      a.Running,
		Progress:     a.Progress,
		Log:          logs,
		Results:      results,
		Error:        a.Error,
		StartedAt:    a.StartedAt,
		FinishedAt:   a.FinishedAt,
		NetCheck:     a.NetCheck,
		IPv6Info:     a.IPv6Info,
		DNSState:     a.DNSState,
		Guard:        guard,
		Sched:        sched,
		HistoryCount: hCount,
		CfgSnapshot: map[string]any{
			"mode":           cfg.Mode,
			"latency_rounds": cfg.LatencyRounds,
			"warmup_discard": cfg.WarmupDiscard,
			"cfcolo":         cfg.CfColo,
			"routines":       cfg.Routines,
		},
	}
}

// ---------------------------------------------------------------- 执行

// runTask 跑一轮完整测速。
func (a *App) runTask(cfg engine.Config, reason string) {
	t0 := time.Now()
	a.mu.Lock()
	if a.Running {
		a.mu.Unlock()
		return
	}
	a.Running = true
	a.Error = ""
	a.StartedAt = time.Now().Format("2006-01-02 15:04:05")
	a.FinishedAt = ""
	a.Progress = engine.Progress{Stage: "check", Label: "网络自检", Done: 0, Total: 1}
	a.mu.Unlock()

	a.logSep("开始测速（" + reason + "）")
	defer func() {
		a.mu.Lock()
		a.Running = false
		a.runner = nil
		a.FinishedAt = time.Now().Format("2006-01-02 15:04:05")
		if a.Progress.Stage != "done" && a.Error == "" {
			a.Progress.Stage = "done"
			a.Progress.Label = "完成"
		}
		a.mu.Unlock()
		a.logSep("本轮结束")
	}()

	// 网络自检：有些网络会把 TCP SYN 在本地应答，ping 模式测不出差异
	nc := engine.CheckNet(1500 * time.Millisecond)
	a.mu.Lock()
	a.NetCheck = nc
	a.mu.Unlock()
	if nc.Hijacked {
		a.log("[警告] " + nc.Advice)
		if strings.EqualFold(cfg.Mode, "ping") {
			a.log("[警告] 当前模式仍是 TCP ping，延迟会全部挤在 1ms 附近，请改选 TLS 模式。")
		}
	}

	runner := engine.NewRunner(cfg, a.DataDir,
		func(p engine.Progress) {
			a.mu.Lock()
			a.Progress = p
			a.mu.Unlock()
		},
		a.log)
	a.mu.Lock()
	a.runner = runner
	a.mu.Unlock()

	results, err := runner.Run()
	if err != nil {
		a.mu.Lock()
		a.Error = err.Error()
		a.mu.Unlock()
		a.log("执行失败：" + err.Error())
		return
	}

	info := runner.IPv6Info
	a.mu.Lock()
	a.Results = results
	if info.Target != "" || info.Reason != "" {
		a.IPv6Info = map[string]any{
			"ok": info.OK, "reason": info.Reason, "local": info.Local,
			"target": info.Target, "ms": info.MS, "checked": true,
		}
	}
	auto := cfg.DNS.AutoSync
	a.mu.Unlock()

	dur := time.Since(t0).Seconds()
	a.persistLast(results)
	a.recordHistory(reason, dur, results)

	if auto && len(results) > 0 {
		if best := engine.Best(results); best != nil {
			a.doSync(cfg, best.IP, true)
		}
	}
}

func (a *App) recordHistory(reason string, dur float64, results []*engine.Result) {
	now := time.Now()
	item := HistoryItem{
		ID:        now.Format("20060102150405"),
		Time:      now.Format("2006-01-02 15:04:05"),
		Reason:    reason,
		DurationS: float64(int64(dur*10+0.5)) / 10,
		Count:     len(results),
		Results:   results,
	}
	if best := engine.Best(results); best != nil {
		item.BestIP = best.IP
		item.BestColo = best.Colo
		if best.DelayMS != nil {
			item.BestDelay = *best.DelayMS
		}
		if best.SpeedKBps != nil {
			item.BestSpeed = *best.SpeedKBps
		}
	}
	a.mu.Lock()
	a.History = append([]HistoryItem{item}, a.History...)
	if len(a.History) > maxHistory {
		a.History = a.History[:maxHistory]
	}
	a.mu.Unlock()
	a.persistHistory()
}

func (a *App) persistHistory() {
	a.mu.Lock()
	list := append([]HistoryItem{}, a.History...)
	a.mu.Unlock()

	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	tmp := a.DataDir + "/history.json.tmp"
	if err := writeFile(tmp, b); err != nil {
		return
	}
	_ = rename(tmp, a.DataDir+"/history.json")
}

func (a *App) restoreHistory() {
	b, err := readFile(a.DataDir + "/history.json")
	if err != nil {
		return
	}
	var list []HistoryItem
	if err := json.Unmarshal(b, &list); err == nil {
		a.mu.Lock()
		a.History = list
		a.mu.Unlock()
	}
}

func (a *App) persistLast(results []*engine.Result) {
	obj := map[string]any{
		"time":    time.Now().Format("2006-01-02 15:04:05"),
		"results": results,
	}
	b, err := json.MarshalIndent(obj, "", " ")
	if err != nil {
		return
	}
	tmp := a.DataDir + "/last_result.json.tmp"
	if err := writeFile(tmp, b); err != nil {
		return
	}
	_ = rename(tmp, a.DataDir+"/last_result.json")
}

func (a *App) restoreLast() {
	a.restoreHistory()
	b, err := readFile(a.DataDir + "/last_result.json")
	if err != nil {
		return
	}
	var obj struct {
		Time    string           `json:"time"`
		Results []*engine.Result `json:"results"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return
	}
	a.Results = obj.Results
	a.FinishedAt = obj.Time
}

// ---------------------------------------------------------------- DNS 同步

// doSync 把 bestIP 写入全部 AdGuard 实例。
func (a *App) doSync(cfg engine.Config, bestIP string, auto bool) {
	if bestIP == "" {
		a.log("DNS 同步跳过：没有可写入的最优 IP")
		return
	}
	if auto && !cfg.DNS.AutoSync {
		return
	}
	n := len(cfg.DNS.Instances)
	if n == 0 {
		if !auto {
			a.log("DNS 同步跳过：尚未配置任何实例")
		}
		return
	}
	tag := "手动"
	if auto {
		tag = "自动"
	}
	a.log(fmt.Sprintf("DNS %s同步开始：%s → %d 个实例 / %d 个域名",
		tag, bestIP, n, len(cfg.DNS.Domains)))
	res := adguard.SyncInstances(cfg.DNS, bestIP, a.log)
	autoFlag := auto
	a.mu.Lock()
	a.DNSState = DNSState{
		LastIP:    bestIP,
		LastSync:  time.Now().Format("2006-01-02 15:04:05"),
		Auto:      &autoFlag,
		Instances: res,
	}
	// 立即联动守护目标：DNS 已成功写入新 IP，守护目标立即对齐并清零失败计数
	a.Guard.WatchIP = bestIP
	a.Guard.Fails = 0
	a.mu.Unlock()
	a.wakeGuard()
}

// BestIP 从结果里选要写入 DNS 的 IP：实测带宽最大的那一个。
func BestIP(rows []*engine.Result) string {
	if r := engine.Best(rows); r != nil {
		return r.IP
	}
	return ""
}

// tryFailover 尝试把 DNS 从失效 IP 切到一个备选 IP。返回 true 表示已切换。
//
// 流程：挑备选 → 实测一次确认真的活着 → 写 DNS → 更新守护盯的目标。
// 「先探后切」很关键：结果表里的延迟是上一轮的数据，可能已经过期，
// 直接切过去有可能切到另一个死 IP，白白让全屋断网一次。
func (a *App) tryFailover(cfg engine.Config, deadIP, now string) bool {
	a.failoverMu.Lock()
	defer a.failoverMu.Unlock()

	if a.failedIPs == nil {
		a.failedIPs = map[string]struct{}{}
	}
	a.failedIPs[deadIP] = struct{}{}

	if len(a.failedIPs) > 64 {
		a.failedIPs = map[string]struct{}{deadIP: {}}
	}

	r := a.pickFallback(a.failedIPs)
	if r == nil {
		a.log(fmt.Sprintf("守护：%s 不可达，且结果表里已无可用备选（已试 %d 个），转整轮重测",
			deadIP, len(a.failedIPs)))
		return false
	}

	// 先实测确认备选可用
	timeout := time.Duration(cfg.Guard.ProbeTimeout) * time.Second
	ok, rtt, _, errMsg := engine.ProbeAlive(r.IP, cfg.Mode, cfg.Port, cfg.TestURL, timeout)
	if !ok {
		a.failedIPs[r.IP] = struct{}{}
		a.log(fmt.Sprintf("守护：备选 %s 实测不可达（%s），继续找下一个", r.IP, errMsg))
		return false
	}

	a.log(fmt.Sprintf("守护：故障轮换 %s → %s（实测 %.0fms），跳过整轮重测", deadIP, r.IP, rtt))
	a.mu.Lock()
	a.Guard.LastRerun = now
	a.Guard.RerunCount++
	a.Guard.Fails = 0
	a.Guard.WatchIP = r.IP
	okCopy := true
	a.Guard.OK = &okCopy
	rr := round1(rtt)
	a.Guard.RTTMS = &rr
	a.mu.Unlock()

	// 写 DNS（异步，避免阻塞守护循环）
	go a.doSync(cfg, r.IP, true)
	return true
}

// ---------------------------------------------------------------- 守护

// watchIP 当前该盯哪个 IP：优先 DNS 已同步的，其次上一轮测速的最优。
func (a *App) watchIP() string {
	a.mu.Lock()
	ip := a.DNSState.LastIP
	rows := a.Results
	a.mu.Unlock()
	if ip != "" {
		return ip
	}
	return BestIP(rows)
}

// pickFallback 从上一轮结果里挑一个「不是 dead」且排序最靠前的 IP 作为替补。
//
// 为什么要备选轮换：守护发现当前 IP 挂了就整轮重测，代价是几分钟。
// 而上一轮测速的结果里往往还有 10 个以上可用 IP，直接切过去只要 100ms。
// 只有备选也全部探测失败时，才值得花几分钟重测。
//
// 排序口径与写 DNS 时的「最优」一致（带宽优先），保证切过去的是次优解而不是随便一个。
func (a *App) pickFallback(exclude map[string]struct{}) *engine.Result {
	a.mu.Lock()
	rows := append([]*engine.Result{}, a.Results...)
	a.mu.Unlock()

	sort.SliceStable(rows, func(i, j int) bool { return engine.SpeedOrder(rows[i], rows[j]) })
	for _, r := range rows {
		if r == nil || r.IP == "" {
			continue
		}
		if _, skip := exclude[r.IP]; skip {
			continue
		}
		// 至少要有延迟数据，否则不知道它是否活着
		if r.DelayMS == nil {
			continue
		}
		return r
	}
	return nil
}

func (a *App) wakeGuard() {
	if a.guardWake == nil {
		return
	}
	select {
	case a.guardWake <- struct{}{}:
	default:
	}
}

func (a *App) startGuard() {
	a.guardStop = make(chan struct{})
	a.log("可达性守护已启动")
	go a.guardLoop()
}

func (a *App) guardLoop() {
	for {
		select {
		case <-a.guardStop:
			return
		default:
		}
		cfg := a.Store.Load()
		g := cfg.Guard
		interval := g.IntervalSec
		if interval < 15 {
			interval = 60
		}
		a.mu.Lock()
		a.Guard.Enabled = g.Enabled
		a.Guard.NextCheck = time.Now().Add(time.Duration(interval) * time.Second).Format("15:04:05")
		a.mu.Unlock()

		if !g.Enabled {
			if !sleepOrStopOrWake(a.guardStop, a.guardWake, time.Duration(interval)*time.Second) {
				return
			}
			continue
		}
		ip := a.watchIP()
		if ip == "" {
			if !sleepOrStopOrWake(a.guardStop, a.guardWake, time.Duration(interval)*time.Second) {
				return
			}
			continue
		}

		timeout := time.Duration(g.ProbeTimeout) * time.Second
		ok, rtt, _, errMsg := engine.ProbeAlive(ip, cfg.Mode, cfg.Port, cfg.TestURL, timeout)

		now := time.Now().Format("2006-01-02 15:04:05")
		var fails int
		var prevRerun int64
		var wasFailing bool
		a.mu.Lock()
		gs := &a.Guard
		wasFailing = gs.Fails > 0
		gs.WatchIP = ip
		gs.Checks++
		gs.LastCheck = now
		okCopy := ok
		gs.OK = &okCopy
		if ok {
			gs.RTTMS = &rtt
			gs.Fails = 0
			gs.LastOK = now
			gs.LastError = ""
		} else {
			gs.RTTMS = nil
			gs.Fails++
			gs.FailTotal++
			gs.LastError = errMsg
		}
		var rttPtr *float64
		if ok {
			r := round1(rtt)
			rttPtr = &r
		}
		tick := GuardTick{T: now[11:], OK: ok, RTT: rttPtr}
		if !ok {
			e := errMsg
			if len(e) > 60 {
				e = e[:60]
			}
			tick.Err = e
		}
		gs.History = append(gs.History, tick)
		if len(gs.History) > guardHist {
			gs.History = gs.History[len(gs.History)-guardHist:]
		}
		fails = gs.Fails
		prevRerun = atomic.LoadInt64(&lastRerunTS)
		a.mu.Unlock()

		if ok {
			if wasFailing {
				a.log(fmt.Sprintf("守护：%s 快速复核通过，节点已恢复正常（%.0fms）", ip, rtt))
			} else {
				a.log(fmt.Sprintf("守护：%s 正常 %.0fms", ip, rtt))
			}
		}

		// 失败快速复核机制：未达连续阈值前，不等完整大周期，固定 15 秒后快速复核一次
		retryDelay := 15 * time.Second
		if time.Duration(interval)*time.Second < retryDelay {
			retryDelay = time.Duration(interval) * time.Second
		}

		if !ok && fails < g.FailThreshold {
			a.log(fmt.Sprintf("守护：%s 首次探测超时（%d/%d，%d秒后快速复核）%s",
				ip, fails, g.FailThreshold, int(retryDelay.Seconds()), errMsg))
			a.mu.Lock()
			a.Guard.NextCheck = time.Now().Add(retryDelay).Format("15:04:05")
			a.mu.Unlock()
			if !sleepOrStopOrWake(a.guardStop, a.guardWake, retryDelay) {
				return
			}
			continue
		}

		// 连续失败达到阈值 → 判定不可达，先试备选轮换，备选也不可用才重测
		if !ok && fails >= g.FailThreshold {
			a.log(fmt.Sprintf("守护：%s 连续 %d 次探测失败，确认节点失效！", ip, fails))
			cooldown := g.RerunCooldownS
			if cooldown < 60 {
				cooldown = 900
			}
			elapsed := time.Now().Unix() - prevRerun

			// ① 故障快速轮换：从上一轮结果里换一个可用 IP，秒级生效
			//    同一轮里连续切换要防死循环，用 tried 记录已经试过的 IP
			if g.FailoverEnabled() {
				switched := a.tryFailover(cfg, ip, now)
				if switched {
					if !sleepOrStopOrWake(a.guardStop, a.guardWake, time.Duration(interval)*time.Second) {
						return
					}
					continue
				}
			}

			switch {
			case elapsed < int64(cooldown):
				a.log(fmt.Sprintf("守护：已判定 %s 不可达，但距上次重测不足 %d 分钟，暂缓",
					ip, cooldown/60))
			case !g.AutoRerun:
				a.log(fmt.Sprintf("守护：%s 已判定不可达（自动重测已关闭）", ip))
			case a.isRunning():
				a.log("守护：已有测速任务在跑，跳过本次重测")
			default:
				a.log(fmt.Sprintf("守护：%s 连续 %d 次失败，自动触发重测", ip, fails))
				a.mu.Lock()
				a.Guard.LastRerun = now
				atomic.StoreInt64(&lastRerunTS, time.Now().Unix())
				a.Guard.RerunCount++
				a.Guard.Fails = 0
				a.mu.Unlock()
				go a.runTask(cfg, "守护·节点失效")
			}
		}

		// 定期强制刷新
		if g.RefreshSec > 0 && ok {
			if time.Now().Unix()-atomic.LoadInt64(&lastRefreshTS) >= int64(g.RefreshSec) {
				atomic.StoreInt64(&lastRefreshTS, time.Now().Unix())
				if !a.isRunning() {
					a.log(fmt.Sprintf("守护：到达定时刷新周期（%d 分钟），重新测速", g.RefreshSec/60))
					go a.runTask(cfg, "守护·定时刷新")
				}
			}
		}

		if !sleepOrStopOrWake(a.guardStop, a.guardWake, time.Duration(interval)*time.Second) {
			return
		}
	}
}

func (a *App) isRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Running
}

func sleepOrStop(stop chan struct{}, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
	case <-t.C:
	}
}

func sleepOrStopOrWake(stop, wake chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
		return false
	case <-wake:
		return true
	case <-t.C:
		return true
	}
}

// ---------------------------------------------------------------- HTTP

// Handler 返回配置好路由的 http.Handler。
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok")
	})
	// 登录 / 登出 / 鉴权状态：自身不走 auth（否则没登录就登不进去）
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.auth(a.handleLogout))
	mux.HandleFunc("/api/auth", a.handleAuthState)
	mux.HandleFunc("/api/config", a.auth(a.handleConfig))
	mux.HandleFunc("/api/state", a.auth(a.handleState))
	mux.HandleFunc("/api/run", a.auth(a.handleRun))
	mux.HandleFunc("/api/cancel", a.auth(a.handleCancel))
	mux.HandleFunc("/api/dns", a.auth(a.handleDNS))
	mux.HandleFunc("/api/dns/save", a.auth(a.handleDNSSave))
	mux.HandleFunc("/api/dns/sync", a.auth(a.handleDNSSync))
	mux.HandleFunc("/api/dns/test", a.auth(a.handleDNSTest))
	mux.HandleFunc("/api/dns/rewrites", a.auth(a.handleDNSRewrites))
	mux.HandleFunc("/api/guard/probe", a.auth(a.handleGuardProbe))
	mux.HandleFunc("/api/export", a.auth(a.handleExport))
	mux.HandleFunc("/api/history", a.auth(a.handleHistory))
	mux.HandleFunc("/api/history/clear", a.auth(a.handleHistoryClear))

	// 统一网关前缀适配：飞牛统一网关把 /app/cfip-opt 前缀透传过来，
	// 剥掉此前缀后再交给 mux 处理，同时支持根路径直接访问。
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/app/cfip-opt"
		p := r.URL.Path
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			r.URL.Path = strings.TrimPrefix(p, prefix)
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "index missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// auth 统一鉴权中间件：先过来源门禁，再验身份。
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ① 来源网段门禁
		if !a.gate.Allow(r.RemoteAddr) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "来源地址不在允许的网段内（CFIP_ALLOWED_CIDRS）",
			})
			return
		}
		// ② 身份认证
		if a.authed(r) {
			next(w, r)
			return
		}
		// 浏览器访问页面时给 Basic 质询，脚本调用时给 JSON 错误
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("WWW-Authenticate", `Basic realm="cfip-opt"`)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录或会话已过期"})
	}
}

// handleLogin 口令换 token，返回 {"token": "..."} 并种 Cookie。
// 路径与响应结构对齐原应用 cf-dns-select 的 POST /api/login。
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "只支持 POST"})
		return
	}
	// 登录接口本身也要过门禁，否则等于给攻击者留了爆破入口
	if !a.gate.Allow(r.RemoteAddr) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "来源地址不在允许的网段内"})
		return
	}
	pwd := a.needsAuth()
	var body struct {
		Password string `json:"password"`
	}
	if raw := readBody(r); raw != nil {
		if b, ok := raw["password"]; ok {
			_ = json.Unmarshal(b, &body.Password)
		}
	}
	// 没设口令时直接发 token（等价于「公开模式」），方便内网裸用
	if pwd != "" && !checkPassword(body.Password, pwd) {
		// 故意慢一点，抬高在线爆破成本
		time.Sleep(300 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "口令错误"})
		return
	}
	tok := a.sessions.issue()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(sessionTTL.Seconds())})
}

// handleLogout 失效当前 token。
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.revoke(c.Value)
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		a.sessions.revoke(strings.TrimPrefix(h, "Bearer "))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAuthState 告诉前端「要不要登录、当前是否已登录」。
func (a *App) handleAuthState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"required": a.needsAuth() != "",
		"authed":   a.authed(r),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(b)
}

func readBody(r *http.Request) map[string]json.RawMessage {
	if r.Body == nil {
		return map[string]json.RawMessage{}
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil || len(b) == 0 {
		return map[string]json.RawMessage{}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]json.RawMessage{}
	}
	return m
}

// dropMaskedPassword 口令留空或掩码表示「不修改」。
func dropMaskedPassword(body map[string]json.RawMessage) {
	raw, ok := body["password"]
	if !ok {
		return
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && (s == "" || s == "********") {
		delete(body, "password")
	}
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := a.Store.Load()
		out := toMap(cfg)
		out["password"] = ""
		out["password_set"] = cfg.Password != ""
		writeJSON(w, 200, map[string]any{"config": out, "colos": CommonColos})
	case http.MethodPost:
		body := readBody(r)
		dropMaskedPassword(body)
		cfg, err := a.Store.Merge(body)
		if err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		out := toMap(cfg)
		out["password"] = ""
		a.wakeGuard()
		writeJSON(w, 200, map[string]any{"ok": true, "config": out})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func toMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	json.Unmarshal(b, &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.snapshot(a.Store.Load()))
}

func (a *App) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.isRunning() {
		writeJSON(w, 409, map[string]any{"ok": false, "error": "已有测速在运行"})
		return
	}
	cfg := a.Store.Load()
	body := readBody(r)
	if len(body) > 0 {
		dropMaskedPassword(body)
		if merged, err := a.Store.Merge(body); err == nil {
			cfg = merged
		}
	}
	go a.runTask(cfg, "手动")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	runner := a.runner
	a.mu.Unlock()
	if runner == nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "当前没有任务"})
		return
	}
	runner.Stop()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleExport(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("fmt")
	a.mu.Lock()
	rows := append([]*engine.Result{}, a.Results...)
	a.mu.Unlock()
	switch kind {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="cfip-opt.csv"`)
		io.WriteString(w, engine.FormatCSV(rows))
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		b, _ := json.MarshalIndent(rows, "", "  ")
		w.Write(b)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, engine.FormatText(rows)+"\n")
	}
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	list := append([]HistoryItem{}, a.History...)
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "history": list})
}

func (a *App) handleHistoryClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	a.History = []HistoryItem{}
	a.mu.Unlock()
	a.persistHistory()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- DNS 端点

func maskInstances(insts []engine.DNSInstance) []map[string]any {
	out := make([]map[string]any, 0, len(insts))
	for _, it := range insts {
		pw := ""
		if it.Password != "" {
			pw = "********"
		}
		out = append(out, map[string]any{
			"name": it.Name, "url": it.URL, "username": it.Username, "password": pw,
		})
	}
	return out
}

func (a *App) handleDNS(w http.ResponseWriter, r *http.Request) {
	cfg := a.Store.Load()
	a.mu.Lock()
	ds := a.DNSState
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"dns": map[string]any{
			"auto_sync":       cfg.DNS.AutoSync,
			"instances":       maskInstances(cfg.DNS.Instances),
			"domains":         cfg.DNS.Domains,
			"manual_rewrites": cfg.DNS.ManualRewrites,
		},
		"dns_state": ds,
	})
}

// dnsPayload 前端提交的 dns 段。
type dnsPayload struct {
	AutoSync       bool                 `json:"auto_sync"`
	Instances      []engine.DNSInstance `json:"instances"`
	Domains        []engine.DNSDomain   `json:"domains"`
	ManualRewrites []engine.ManualRewrite `json:"manual_rewrites"`
}

func (a *App) handleDNSSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := readBody(r)
	raw, ok := body["dns"]
	if !ok {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "缺少 dns"})
		return
	}
	var incoming dnsPayload
	if err := json.Unmarshal(raw, &incoming); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cfg := a.Store.Load()
	// 密码为掩码表示「不修改」：按 URL 回填旧密码
	old := make(map[string]string, len(cfg.DNS.Instances))
	for _, it := range cfg.DNS.Instances {
		old[it.URL] = it.Password
	}
	for i := range incoming.Instances {
		if incoming.Instances[i].Password == "" || incoming.Instances[i].Password == "********" {
			incoming.Instances[i].Password = old[incoming.Instances[i].URL]
		}
	}
	cfg.DNS = engine.DNS{
		AutoSync:       incoming.AutoSync,
		Instances:      incoming.Instances,
		Domains:        incoming.Domains,
		ManualRewrites: incoming.ManualRewrites,
	}
	if cfg.DNS.Instances == nil {
		cfg.DNS.Instances = []engine.DNSInstance{}
	}
	if cfg.DNS.Domains == nil {
		cfg.DNS.Domains = []engine.DNSDomain{}
	}
	if cfg.DNS.ManualRewrites == nil {
		cfg.DNS.ManualRewrites = []engine.ManualRewrite{}
	}
	if err := a.Store.Save(cfg); err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "dns": map[string]any{
		"auto_sync":       cfg.DNS.AutoSync,
		"instances":       maskInstances(cfg.DNS.Instances),
		"domains":         cfg.DNS.Domains,
		"manual_rewrites": cfg.DNS.ManualRewrites,
	}})
}

func (a *App) handleDNSSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.isRunning() {
		writeJSON(w, 409, map[string]any{"ok": false, "error": "测速运行中，稍后再试"})
		return
	}
	cfg := a.Store.Load()
	a.mu.Lock()
	rows := a.Results
	a.mu.Unlock()
	best := BestIP(rows)
	if best == "" {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "没有可用的测速结果，请先测速"})
		return
	}
	a.doSync(cfg, best, false)
	a.mu.Lock()
	ds := a.DNSState
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "ip": best, "dns_state": ds})
}

func (a *App) handleDNSTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Instance engine.DNSInstance `json:"instance"`
	}
	json.Unmarshal(mustMarshal(readBody(r)), &payload)
	if strings.TrimSpace(payload.Instance.URL) == "" {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "缺少实例地址"})
		return
	}
	pwd := payload.Instance.Password
	if pwd == "" || pwd == "********" {
		for _, it := range a.Store.Load().DNS.Instances {
			if it.URL == payload.Instance.URL {
				pwd = it.Password
				break
			}
		}
	}
	c := adguard.NewClient(payload.Instance.URL, payload.Instance.Username, pwd)
	rows, err := c.ListRewrites()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "rewrites": len(rows)})
}

func (a *App) handleDNSRewrites(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("url"))
	var found *engine.DNSInstance
	insts := a.Store.Load().DNS.Instances
	for i := range insts {
		if insts[i].URL == target || strings.TrimRight(insts[i].URL, "/") == strings.TrimRight(target, "/") {
			found = &insts[i]
			break
		}
	}
	if found == nil && target == "" && len(insts) > 0 {
		found = &insts[0]
	}
	if found == nil {
		writeJSON(w, 404, map[string]any{"error": "实例不存在"})
		return
	}
	c := adguard.NewClient(found.URL, found.Username, found.Password)
	rows, err := c.ListRewrites()
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"rewrites": rows})
}

func (a *App) handleGuardProbe(w http.ResponseWriter, r *http.Request) {
	ip := a.watchIP()
	if ip == "" {
		writeJSON(w, 400, map[string]any{"error": "暂无可用 IP（请先跑一次测速）"})
		return
	}
	cfg := a.Store.Load()
	ok, rtt, colo, errMsg := engine.ProbeAlive(ip, cfg.Mode, cfg.Port, cfg.TestURL,
		time.Duration(cfg.Guard.ProbeTimeout)*time.Second)
	resp := map[string]any{"ip": ip, "ok": ok, "colo": colo, "error": errMsg}
	if ok {
		resp["rtt_ms"] = round1(rtt)
	} else {
		resp["rtt_ms"] = nil
	}
	writeJSON(w, 200, resp)
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ---------------------------------------------------------------- 启动

// ListenAndServe 启动 HTTP 服务。
// ListenAndServeUnix 在 Unix 域套接字上提供服务。
//
// 飞牛原生应用不暴露端口：CGI 网关把请求转给这个套接字。
// 比监听 TCP 更安全（外部连不进来），也避开端口冲突。
func (a *App) ListenAndServeUnix(sockPath string) error {
	// 残留的 socket 文件会让 Listen 报 "address already in use"。
	// 先探一下：能连上说明真有实例在跑（不该启动第二个），连不上就是陈尸，删掉。
	if _, err := os.Stat(sockPath); err == nil {
		c, derr := net.DialTimeout("unix", sockPath, 400*time.Millisecond)
		if derr == nil {
			c.Close()
			return fmt.Errorf("套接字 %s 已被占用，可能已有一个 cfip-opt 在运行", sockPath)
		}
		_ = os.Remove(sockPath)
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		return err
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	// 让同组用户也能访问（飞牛以 package 用户在 CGI 里连接）
	_ = os.Chmod(sockPath, 0o660)

	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// 测速是长请求，不设 WriteTimeout
	}
	return srv.Serve(ln)
}

func (a *App) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

// ParseListen 解析 "0.0.0.0:8787" 形式。
func ParseListen(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "0.0.0.0", 8787
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "0.0.0.0", 8787
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 {
		p = 8787
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, p
}

// 预留字段，供守护使用（放在结构体外部以便加锁访问）。
var _ = atomic.Bool{}
