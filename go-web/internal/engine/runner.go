package engine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Progress 进度回调载荷，字段名与前端一致。
type Progress struct {
	Stage  string `json:"stage"`
	Label  string `json:"label"`
	Done   int    `json:"done"`
	Total  int    `json:"total"`
	Detail string `json:"detail"`
}

// Runner 一次完整测速。
type Runner struct {
	cfg       Config
	dataDir   string
	OnProgress func(Progress)
	OnLog      func(string)

	stop atomic.Bool

	colo *ColoDB

	// IPv6Info 本轮 IPv6 出口探测结果
	IPv6Info IPv6Info

	// Stats 计时统计
	StartedAt time.Time
}

// NewRunner 构造执行器。
func NewRunner(cfg Config, dataDir string, onProgress func(Progress), onLog func(string)) *Runner {
	if onProgress == nil {
		onProgress = func(Progress) {}
	}
	if onLog == nil {
		onLog = func(string) {}
	}
	return &Runner{
		cfg:        cfg,
		dataDir:    dataDir,
		OnProgress: onProgress,
		OnLog:      onLog,
		colo:       NewColoDB(filepath.Join(dataDir, "colo_ip_db.json")),
	}
}

// Stop 请求中止本轮测速。
func (r *Runner) Stop() { r.stop.Store(true) }

func (r *Runner) stopped() bool { return r.stop.Load() }

func (r *Runner) progress(stage, label string, done, total int, detail string) {
	r.OnProgress(Progress{Stage: stage, Label: label, Done: done, Total: total, Detail: detail})
}

// ColoDB 返回地区库（守护流程复用它）。
func (r *Runner) ColoDB() *ColoDB { return r.colo }

// ---------------------------------------------------------------- 主流程

// Run 执行完整四阶段测速。
func (r *Runner) Run() ([]*Result, error) {
	cfg := r.cfg
	r.colo.Load()
	r.StartedAt = time.Now()

	// ---- 1. 装载候选 IP
	r.progress("load", "加载 IP 段", 0, 1, "")
	candidates, err := r.loadCandidates()
	if err != nil {
		return nil, err
	}
	candidates = r.capCandidates(candidates)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("候选 IP 池为空，请检查 IP 段文件")
	}
	n6 := 0
	for _, ip := range candidates {
		if IsV6(ip) {
			n6++
		}
	}
	r.OnLog(fmt.Sprintf("[1/5] 候选 IP：%d 个（IPv4 %d / IPv6 %d）", len(candidates), len(candidates)-n6, n6))

	// 只有真的要测 IPv6 时才做出口检测。每次都重新探测，不用缓存标记：
	// 曾经因为「只探一次」导致首次误判后整个进程生命周期不再重试。
	if n6 > 0 {
		pu := ParseTestURL(cfg.TestURL, cfg.Port)
		extra := []string{}
		if pu.Host != "" {
			extra = append(extra, pu.Host)
		}
		info := IPv6Available(time.Duration(cfg.TimeoutMS)*time.Millisecond, cfg.Port, extra)
		r.IPv6Info = info
		if info.OK {
			r.OnLog(fmt.Sprintf("[1/5] IPv6 出口可用：%s 建连 %.0fms", info.Target, info.MS))
		} else {
			r.OnLog(fmt.Sprintf("[1/5] [警告] %s；IPv6 探测会全部失败，已自动跳过这批地址"+
				"（建议取消勾选「同时测 IPv6」）", info.Reason))
			kept := make([]string, 0, len(candidates))
			for _, ip := range candidates {
				if !IsV6(ip) {
					kept = append(kept, ip)
				}
			}
			candidates = kept
			if len(candidates) == 0 {
				return nil, fmt.Errorf("候选池里只有 IPv6 地址，但本机 IPv6 出口不可用")
			}
		}
	}

	// ---- 2. 地区过滤（前置！）
	//
	// 顺序很关键：先按地区把候选收敛掉，再在「地区已经合格」的池子里
	// 分配延迟探测名额，最后对延迟合格者测速。
	//
	// 旧顺序（延迟 → 地区 → 测速）有两个隐患：
	//   1) 延迟探测的白白浪费——测完才发现地区不合格的 IP 全部作废；
	//   2) 名额在测速阶段才切，v6 经过 max_delay 与地区双重筛选后往往只剩个位数，
	//      空出的名额被 v4 补满，看起来像「没有对半分」，实际是上游供给不足。
	// 前置之后，名额从「地区合格池」里切，供给不足会在日志里明确报出缺口。
	candidates = r.stageGate(candidates)
	if r.stopped() {
		return nil, fmt.Errorf("已取消")
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("地区过滤后没有剩余 IP，请放宽地区选择（cfcolo 留空即不限）" +
			"或先跑一次 httping 模式学习地区库")
	}

	// ---- 3. 延迟测速（名额在地区合格的池子里按地址族对半分）
	latency := r.stageLatency(candidates)
	if r.stopped() {
		return nil, fmt.Errorf("已取消")
	}
	if len(latency) == 0 {
		return nil, fmt.Errorf("延迟测速没有可用结果，请放宽延迟上限或检查网络")
	}

	// ---- 4. 下载测速
	results := r.stageDownload(latency)

	r.colo.Save()
	elapsed := time.Since(r.StartedAt).Seconds()
	r.OnLog(fmt.Sprintf("完成，用时 %.1fs", elapsed))
	r.progress("done", "完成", 1, 1, fmt.Sprintf("用时 %.1fs", elapsed))
	return results, nil
}

// ---------------------------------------------------------------- 阶段 1

func (r *Runner) loadCandidates() ([]string, error) {
	cfg := r.cfg
	files := []string{cfg.IPFile}
	if cfg.IPv6 {
		files = append(files, cfg.IPv6File)
	}
	var sb strings.Builder
	for i, name := range files {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(r.dataDir, name)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("读取 IP 段文件失败：%s（%v）", path, err)
			}
			r.OnLog(fmt.Sprintf("跳过不存在或不可读的 %s", path))
			continue
		}
		sb.Write(b)
		sb.WriteString("\n")
	}
	merged := sb.String()

	hasV6 := false
	for _, ln := range strings.Split(merged, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(t, ":") {
			hasV6 = true
			break
		}
	}
	v6n := cfg.V6PerCIDR
	if v6n < 1 {
		v6n = 1
	}
	if hasV6 {
		r.OnLog(fmt.Sprintf("IP 段中包含 IPv6，每条前缀随机取 %d 个地址参与测速", v6n))
	}
	return ExpandCandidates(merged, cfg.TestAll, cfg.MaxPool, v6n), nil
}

// splitQuota 把总额度按「地址族对半」切开，某族不够时另一族补足。
//
// 为什么必须按族切：IPv4 与 IPv6 候选池大小完全不对等（/24 抽 1 个 vs 每条前缀抽 N 个），
// 只按总量封顶时池子大的一方会把名额吃光，另一方连进延迟阶段的机会都没有。
func splitQuota(capN, n4, n6 int) (int, int) {
	if n4 <= 0 {
		return 0, minInt(capN, n6)
	}
	if n6 <= 0 {
		return minInt(capN, n4), 0
	}
	half := capN / 2
	q4 := minInt(half, n4)
	q6 := minInt(capN-half, n6)
	left := capN - q4 - q6
	if left > 0 {
		add4 := minInt(left, n4-q4)
		q4 += add4
		left -= add4
		add6 := minInt(left, n6-q6)
		q6 += add6
	}
	return q4, q6
}

// sampleEvenly 从 pool 里均匀取 n 个（按索引等距切分），保持原顺序。
//
// 为什么不用随机：候选池是按网段顺序展开的，纯随机取容易扎堆在少数网段，
// 导致「补探了 n 个但全在同一个 /16 里」这种假覆盖。等距切分保证取样
// 横跨整个池子，网段覆盖均匀。
func sampleEvenly(pool []string, n int) []string {
	if n <= 0 || len(pool) == 0 {
		return nil
	}
	if len(pool) <= n {
		return append([]string{}, pool...)
	}
	out := make([]string, 0, n)
	step := float64(len(pool)) / float64(n)
	for i := 0; i < n; i++ {
		idx := int(float64(i) * step)
		if idx >= len(pool) {
			idx = len(pool) - 1
		}
		out = append(out, pool[idx])
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// pickFromPool 从一个地址族的候选池里挑 capN 个：历史优质优先 → 分块覆盖 → 随机补满。
func (r *Runner) pickFromPool(pool []string, capN int, rng *rand.Rand) []string {
	if capN <= 0 || len(pool) == 0 {
		return nil
	}
	if len(pool) <= capN {
		return append([]string{}, pool...)
	}
	picked := make([]string, 0, capN)
	seen := make(map[string]struct{}, capN)

	// 1) 历史优质 IP 优先（零成本复用经验）
	hist := make([]string, 0, capN)
	for _, ip := range pool {
		if r.colo.Get(ip) != "" {
			hist = append(hist, ip)
		}
	}
	sort.Strings(hist)
	for _, ip := range hist {
		if len(picked) >= capN {
			break
		}
		picked = append(picked, ip)
		seen[ip] = struct{}{}
	}

	// 2) 分块覆盖，避免全挤在同一网段
	blocks := make(map[string][]string, 256)
	order := make([]string, 0, 256)
	for _, ip := range pool {
		if _, ok := seen[ip]; ok {
			continue
		}
		k := BlockKey(ParseIP(ip))
		if _, ok := blocks[k]; !ok {
			order = append(order, k)
		}
		blocks[k] = append(blocks[k], ip)
	}
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for _, k := range order {
		if len(picked) >= capN {
			break
		}
		cands := blocks[k]
		ip := cands[rng.Intn(len(cands))]
		picked = append(picked, ip)
		seen[ip] = struct{}{}
	}

	// 3) 还差就随机补满
	if len(picked) < capN {
		rest := make([]string, 0, len(pool)-len(picked))
		for _, ip := range pool {
			if _, ok := seen[ip]; !ok {
				rest = append(rest, ip)
			}
		}
		rng.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
		need := capN - len(picked)
		if need > len(rest) {
			need = len(rest)
		}
		picked = append(picked, rest[:need]...)
	}
	if len(picked) > capN {
		picked = picked[:capN]
	}
	return picked
}

// capCandidates 延迟阶段候选上限。
//
// 语义：latency_cap = 800 且两族都有货时，就是 IPv4 400 + IPv6 400，
// 各走各的名额互不挤占。某族不足一半时余量自动让给另一族。
// 这不是「随机抽 20 个」——只有下载阶段才按延迟取前 N 个。
func (r *Runner) capCandidates(candidates []string) []string {
	capN := r.cfg.LatencyCap
	// 去重保序
	seen := make(map[string]struct{}, len(candidates))
	pool := make([]string, 0, len(candidates))
	for _, ip := range candidates {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		pool = append(pool, ip)
	}
	total := len(pool)
	if capN <= 0 || total <= capN {
		return pool
	}

	v4 := make([]string, 0, total)
	v6 := make([]string, 0, total)
	for _, ip := range pool {
		if IsV6(ip) {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	q4, q6 := splitQuota(capN, len(v4), len(v6))
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	picked := append(r.pickFromPool(v4, q4, rng), r.pickFromPool(v6, q6, rng)...)

	got4, got6 := 0, 0
	for _, ip := range picked {
		if IsV6(ip) {
			got6++
		} else {
			got4++
		}
	}
	r.OnLog(fmt.Sprintf("[2/5] 延迟名额分配：%d 个上限 → IPv4 %d/%d、IPv6 %d/%d，合计 %d 个参与延迟测速",
		capN, got4, q4, got6, q6, len(picked)))
	// 供给不足必须明说，否则用户只会看到一个奇怪的比例而不知道原因
	var deficits []string
	if got4 < q4 {
		deficits = append(deficits, fmt.Sprintf("IPv4 供给不足（缺 %d 个）", q4-got4))
	}
	if got6 < q6 {
		deficits = append(deficits, fmt.Sprintf("IPv6 供给不足（缺 %d 个）", q6-got6))
	}
	if len(deficits) > 0 {
		r.OnLog("[2/5] [提示] " + strings.Join(deficits, "、") +
			"：这是地区合格的候选池本身数量不够，空出的名额已让给另一族，不是对半规则失效")
	}
	return picked
}

// ---------------------------------------------------------------- 阶段 2

func (r *Runner) stageLatency(candidates []string) []*Result {
	cfg := r.cfg
	mode := strings.ToLower(cfg.Mode)
	// 三种模式统一按 latency_rounds 采样。httping 早先被硬编码成 1 次是
	// 为了省 CF Worker 额度；测速源换成 Cloudflare 官方地址后这个约束不存在了，
	// 单次样本既看不出抖动也扛不住一次偶发抖动，稳定性必须靠多轮样本才能算出来。
	rounds := cfg.LatencyRounds
	if rounds < 1 {
		rounds = 1
	}
	// warm-up 对 httping 同样有意义：首轮含 DNS/TCP/TLS 建连，RTT 偏高
	warmup := cfg.WarmupDiscard && rounds >= 2
	totalProbes := rounds
	if warmup {
		totalProbes++
	}
	gap := time.Duration(cfg.RoundGapMS) * time.Millisecond
	timeout := time.Duration(cfg.TimeoutDurMS()) * time.Millisecond
	port := cfg.Port
	pu := ParseTestURL(cfg.TestURL, port)
	routines := cfg.Routines
	if routines < 1 {
		routines = 64
	}

	// fast_fail：连续失败 >= failCap 次即停止本轮剩余轮次。
	// 默认 2 = 前两次都失败，第三次及之后直接跳过。
	failCap := int(cfg.FastFail)
	if failCap < 0 {
		failCap = 0
	}
	stopAfter := 0
	if failCap >= 2 {
		stopAfter = failCap
	}
	note := ""
	if stopAfter > 0 {
		note = fmt.Sprintf("，连续失败 %d 次即放弃该 IP", failCap)
	}
	warmNote := ""
	if warmup {
		warmNote = "（+1 次 warm-up 预热）"
	}
	r.OnLog(fmt.Sprintf("[3/5] 延迟测速：%s 模式，每 IP %d 次采样%s，并发 %d%s",
		mode, rounds, warmNote, routines, note))

	var done int64
	var gaveUp int64
	results := make([]*Result, 0, len(candidates))
	var mu sync.Mutex

	type job struct{ ip string }
	jobs := make(chan string)
	var wg sync.WaitGroup

	for w := 0; w < routines; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if r.stopped() {
					continue
				}
				samples, colo, aborted := r.probeOne(ip, mode, pu, port, timeout, rounds, totalProbes, gap, stopAfter)
				if aborted {
					atomic.AddInt64(&gaveUp, 1)
				}
				cur := int(atomic.AddInt64(&done, 1))
				if len(samples) > 0 {
					mean, sigma, hasSigma, ok := MeanSigma(samples)
					if ok {
						res := &Result{
							IP:          ip,
							Colo:        colo,
							DelayMS:     F(mean),
							DelayOK:     len(samples),
							DelayRounds: rounds,
							LossRate:    maxF(0, 1-float64(len(samples))/float64(maxInt(1, rounds))),
						}
						if hasSigma {
							res.DelaySigma = F(sigma)
						}
						mu.Lock()
						results = append(results, res)
						mu.Unlock()
					}
				}
				r.progress("latency", "延迟测速中", cur, len(candidates), ip)
			}
		}()
	}

feed:
	for _, ip := range candidates {
		if r.stopped() {
			break
		}
		select {
		case jobs <- ip:
		default:
			jobs <- ip
		}
		if r.stopped() {
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	// 延迟上限 / 丢包过滤
	maxDelay := cfg.MaxDelay
	maxLoss := cfg.LossLimit()
	before := len(results)
	kept := make([]*Result, 0, before)
	for _, res := range results {
		if maxDelay > 0 && res.DelayMS != nil && *res.DelayMS > maxDelay {
			continue
		}
		if res.LossRate > maxLoss {
			continue
		}
		kept = append(kept, res)
	}
	r.OnLog(fmt.Sprintf("[3/5] 延迟测速完成：%d/%d 个 IP 有响应（握手失败或无样本 %d 个）",
		before, len(candidates), len(candidates)-before))
	if stopAfter > 0 && gaveUp > 0 {
		r.OnLog(fmt.Sprintf("[3/5] 提前放弃 %d 个 IP（连续 %d 次不可达，剩余轮次未执行）", gaveUp, stopAfter))
	}
	r.OnLog(fmt.Sprintf("[3/5] 按延迟/丢包过滤后可用 %d/%d 个", len(kept), before))

	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i].DelayMS, kept[j].DelayMS
		if a == nil {
			return false
		}
		if b == nil {
			return true
		}
		return *a < *b
	})
	return kept
}

// probeOne 测单个 IP。返回 (samples, colo, 是否因连续失败提前放弃)。
//
// 三种模式都按 latency_rounds 做多轮采样，语义完全一致：
// 均值看水平，标准差看稳定性，成功率看丢包。
//
// httping 曾经只探 1 次（省 CF Worker 额度），现在测速源已换成 Cloudflare
// 官方地址，额度不再是约束，所以和 ping/tls 一样多轮采样——单次样本无法
// 反映抖动，一个偶然 20ms 的 IP 会被误判成最优。
func (r *Runner) probeOne(ip, mode string, pu ParsedURL, port int, timeout time.Duration,
	rounds, totalProbes int, gap time.Duration, stopAfter int) ([]float64, string, bool) {

	samples := make([]float64, 0, totalProbes)
	colo := ""
	aborted := false

	if mode == "httping" {
		consecFail := 0
		firstOK := false
		for i := 0; i < totalProbes; i++ {
			if r.stopped() {
				break
			}
			rtt, c, _, err := HTTPHead(ip, pu, timeout)
			if err == nil && rtt > 0 {
				samples = append(samples, rtt)
				consecFail = 0
				if i == 0 {
					firstOK = true
				}
				// 顺带学习地区：任一轮拿到 colo 就够，后续 ping 模式可走库
				if c != "" && colo == "" {
					colo = c
					r.colo.Set(ip, c)
				}
			} else {
				consecFail++
				if stopAfter > 0 && consecFail >= stopAfter {
					// 连续失败达阈值：剩余轮次跳过，已采样本保留
					aborted = true
					break
				}
			}
			if gap > 0 && i+1 < totalProbes {
				time.Sleep(gap)
			}
		}
		if r.cfg.WarmupDiscard && r.cfg.LatencyRounds >= 2 && firstOK && len(samples) >= 3 {
			samples = samples[1:]
		}
		return samples, colo, aborted
	}

	firstOK := false
	consecFail := 0
	for i := 0; i < totalProbes; i++ {
		if r.stopped() {
			break
		}
		var rtt float64
		var ok bool
		if mode == "tls" {
			rtt, ok = TLSRTT(ip, port, pu.Host, timeout)
		} else {
			rtt, ok = TCPRTT(ip, port, timeout)
		}
		if ok {
			samples = append(samples, rtt)
			consecFail = 0
			if i == 0 {
				firstOK = true
			}
		} else {
			consecFail++
			if stopAfter > 0 && consecFail >= stopAfter {
				// 连续失败达阈值：剩余轮次直接跳过，
				// 已采到的成功样本保留（前面通过后面才抖的 IP 不该被误杀）
				aborted = true
				break
			}
		}
		if gap > 0 && i+1 < totalProbes {
			time.Sleep(gap)
		}
	}

	// 丢弃 warm-up 首轮：仅当剩余样本仍 >=2 时才丢，否则会把
	// 「首轮成功、后续抖动失败」的有效 IP 误判为不可用。
	//
	// httping 同样适用：首轮要完成 TCP+TLS 建连与 HTTP 往返，RTT 明显高于
	// 后续同连接复用，不丢会把整体均值抬高几十毫秒。
	if r.cfg.WarmupDiscard && r.cfg.LatencyRounds >= 2 && firstOK && len(samples) >= 3 {
		samples = samples[1:]
	}
	return samples, colo, aborted
}

// stageGate 地区过滤（前置阶段）：把候选 IP 收敛到「地区合格」的集合。
//
// 策略是「库优先 + 限量补探」：
//  1. 先查 colo_ip_db.json 的历史学习结果，命中的直接判定，零请求；
//  2. 库中没有的，只补探**够用为止**——目标是给下面的延迟阶段凑够
//     latency_cap 所需的候选（按族各凑一半，再多留一点余量），
//     而不是把整个候选池都探一遍；
//  3. 探到的地区写回库，下一轮直接命中，补探量逐轮下降。
//
// 为什么补探要限量：前置地区过滤意味着目标地区以外的 IP 全部作废，
// 探得再多也只是白花时间。5998 个候选全探一遍要 3 分钟以上（实测
// 32 并发 2 分钟只推进到 2300 个），而延迟阶段真正用得上的只有
// latency_cap 个。限量的代价是「可能漏掉一些好 IP」，但换来的是
// 单轮耗时从分钟级降到十几秒——对一个定时任务来说这个取舍是对的；
// 需要穷举时把 region_probe_unknown 打开即可。
//
// 返回 IP 列表（此时还没有延迟数据，延迟测速在下一阶段做）。
func (r *Runner) stageGate(ips []string) []string {
	cfg := r.cfg
	coloCfg := strings.TrimSpace(cfg.CfColo)
	if coloCfg == "" {
		return ips
	}
	wanted := make(map[string]struct{}, 8)
	for _, c := range strings.Split(coloCfg, ",") {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			wanted[c] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return ips
	}

	timeout := time.Duration(cfg.TimeoutDurMS()) * time.Millisecond
	pu := ParseTestURL(cfg.TestURL, cfg.Port)
	routines := cfg.Routines
	if routines < 1 {
		routines = 64
	}

	keys := make([]string, 0, len(wanted))
	for k := range wanted {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 先做一次库命中统计，决定这一轮要补探多少
	var hitIPs, missIPs []string
	for _, ip := range ips {
		if r.colo.Get(ip) != "" {
			hitIPs = append(hitIPs, ip)
		} else {
			missIPs = append(missIPs, ip)
		}
	}

	// 补探预算：给延迟阶段凑够名额（按族各一半）后再多留 1/4 余量。
	// region_probe_unknown=true 时退化为「全探」，保留穷举能力。
	budget4, budget6 := 0, 0
	if cfg.RegionProbeUnknown {
		for _, ip := range missIPs {
			if IsV6(ip) {
				budget6++
			} else {
				budget4++
			}
		}
	} else {
		var hit4, hit6 int
		for _, ip := range hitIPs {
			if IsV6(ip) {
				hit6++
			} else {
				hit4++
			}
		}
		need := cfg.LatencyCap
		if need < 1 {
			need = 1000
		}
		half := need / 2
		budget4 = (half - hit4) * 5 / 4
		budget6 = (half - hit6) * 5 / 4
		if budget4 < 0 {
			budget4 = 0
		}
		if budget6 < 0 {
			budget6 = 0
		}
	}

	// 按族挑出真正要探的子集（保持原顺序，分块均匀取样由 pickFromPool 负责）
	probeList := make([]string, 0, budget4+budget6)
	var miss4, miss6 []string
	for _, ip := range missIPs {
		if IsV6(ip) {
			miss6 = append(miss6, ip)
		} else {
			miss4 = append(miss4, ip)
		}
	}
	if budget4 > 0 {
		probeList = append(probeList, sampleEvenly(miss4, budget4)...)
	}
	if budget6 > 0 {
		probeList = append(probeList, sampleEvenly(miss6, budget6)...)
	}

	r.OnLog(fmt.Sprintf("[2/5] 地区过滤（前置）：目标 %s，候选 %d 个"+
		"（库命中 %d，本轮补探 %d/%d）", strings.Join(keys, ","), len(ips),
		len(hitIPs), len(probeList), len(missIPs)))

	kept := make([]string, 0, len(ips))
	keptMu := sync.Mutex{}
	keep := func(ip, colo string) {
		if _, ok := wanted[strings.ToUpper(colo)]; !ok {
			return
		}
		keptMu.Lock()
		kept = append(kept, ip)
		keptMu.Unlock()
	}

	// 1) 库命中的直接判定
	for _, ip := range hitIPs {
		keep(ip, r.colo.Get(ip))
	}

	// 2) 库中没有的并发补探
	var probed, probed6 int64
	var done int64
	if len(probeList) > 0 {
		jobs := make(chan string)
		var wg sync.WaitGroup
		for w := 0; w < routines; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range jobs {
					if r.stopped() {
						continue
					}
					_, colo, _, _ := HTTPHead(ip, pu, timeout)
					atomic.AddInt64(&probed, 1)
					if IsV6(ip) {
						atomic.AddInt64(&probed6, 1)
					}
					colo = strings.ToUpper(colo)
					if colo != "" {
						r.colo.Set(ip, colo)
						keep(ip, colo)
					}
					cur := int(atomic.AddInt64(&done, 1))
					r.progress("gate", "确认节点地区", cur, len(probeList), ip)
				}
			}()
		}
		for _, ip := range probeList {
			if r.stopped() {
				break
			}
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
	}

	got4, got6 := 0, 0
	for _, ip := range kept {
		if IsV6(ip) {
			got6++
		} else {
			got4++
		}
	}
	msg := fmt.Sprintf("[2/5] 地区过滤完成：保留 %d/%d 个（IPv4 %d / IPv6 %d，补探 %d 次",
		len(kept), len(ips), got4, got6, probed)
	if probed6 > 0 {
		msg += fmt.Sprintf("，其中 IPv6 %d 个", probed6)
	}
	msg += "）"
	r.OnLog(msg)
	r.colo.Save()
	return kept
}

// ---------------------------------------------------------------- 阶段 4

// selectDownloadPool 从地区过滤后的结果里挑出参与下载测速的 IP。
//
// 语义：**按地址族对半分**。top_n=20 → IPv4 取延迟最快 10 + IPv6 取最快 10。
// 不直接全局按延迟取前 20 的原因：IPv6 在本机实测普遍比 IPv4 慢 200ms 以上
// （v4 最快 147ms / v6 最快 362ms），全局排序会让前 20 名清一色 v4，
// v6 连测速机会都没有，「最终按带宽取最优」就成了只比 v4 的单边结论。
func (r *Runner) selectDownloadPool(results []*Result, topN int) []*Result {
	pool := append([]*Result{}, results...)
	sort.SliceStable(pool, func(i, j int) bool {
		a, b := pool[i].DelayMS, pool[j].DelayMS
		if a == nil {
			return false
		}
		if b == nil {
			return true
		}
		return *a < *b
	})
	if !r.cfg.SplitEnabled() {
		if len(pool) > topN {
			return pool[:topN]
		}
		return pool
	}
	v4 := make([]*Result, 0, len(pool))
	v6 := make([]*Result, 0, len(pool))
	for _, x := range pool {
		if IsV6(x.IP) {
			v6 = append(v6, x)
		} else {
			v4 = append(v4, x)
		}
	}
	q4, q6 := splitQuota(topN, len(v4), len(v6))
	chosen := make([]*Result, 0, q4+q6)
	chosen = append(chosen, v4[:minInt(q4, len(v4))]...)
	chosen = append(chosen, v6[:minInt(q6, len(v6))]...)
	// 保持按延迟升序的整体顺序，日志与页面更好读
	sort.SliceStable(chosen, func(i, j int) bool {
		a, b := chosen[i].DelayMS, chosen[j].DelayMS
		if a == nil {
			return false
		}
		if b == nil {
			return true
		}
		return *a < *b
	})
	return chosen
}

func (r *Runner) stageDownload(results []*Result) []*Result {
	cfg := r.cfg
	dl := cfg.Download
	if !dl.Enabled {
		for _, x := range results {
			x.SpeedKBps = nil
			x.SpeedSigma = nil
			x.SpeedOK = 0
			x.SpeedRounds = 0
		}
		return results
	}

	topN := dl.TopN
	if topN < 1 {
		topN = 20
	}
	rounds := dl.Rounds
	if rounds < 1 {
		rounds = 3
	}
	window := time.Duration(dl.WindowSec * float64(time.Second))
	gap := time.Duration(dl.GapMS) * time.Millisecond
	timeout := time.Duration(float64(window.Seconds())+2) * time.Second
	if cfg.TimeoutDurMS() > 0 {
		if t := time.Duration(cfg.TimeoutDurMS()) * time.Millisecond; t > timeout {
			timeout = t
		}
	}
	url := dl.URL
	if url == "" {
		url = cfg.TestURL
	}
	pu := ParseTestURL(url, cfg.Port)

	pool := r.selectDownloadPool(results, topN)
	n6 := 0
	for _, x := range pool {
		if IsV6(x.IP) {
			n6++
		}
	}
	splitNote := ""
	if cfg.SplitEnabled() {
		splitNote = fmt.Sprintf("（按地址族对半：IPv4 %d / IPv6 %d）", len(pool)-n6, n6)
		if n6*2 < len(pool) && len(pool) < topN {
			splitNote += " —— 两族合计不足设定名额"
		}
	} else {
		splitNote = fmt.Sprintf("（混合排序，含 IPv6 %d 个）", n6)
	}
	r.OnLog(fmt.Sprintf("[4/5] 下载测速：从 %d 个候选里取 %d 个 × %d 轮 × %gs 窗口%s",
		len(results), len(pool), rounds, dl.WindowSec, splitNote))
	// 名额让位必须显式提示：用户看到「v4 19 / v6 1」时应该立刻知道
	// 是 v6 供给不足，而不是对半规则没生效
	if cfg.SplitEnabled() && len(pool) > 0 {
		half := topN / 2
		if n6 < minInt(half, topN) && len(pool) >= topN {
			r.OnLog(fmt.Sprintf("[4/5] [提示] IPv6 只选出 %d 个（目标 %d）：地区合格且延迟过关的 "+
				"IPv6 不足，空出的 %d 个名额已让给 IPv4", n6, half, half-n6))
		} else if n6 < half && len(pool) < topN {
			r.OnLog(fmt.Sprintf("[4/5] [提示] 地区合格的 IP 总共只有 %d 个（少于设定 %d），"+
				"其中 IPv6 %d 个：不是对半规则失效，是候选池供给不足", len(pool), topN, n6))
		}
	}

	// 下载测速并发：原版是串行（每轮窗口 5s × 3 轮 × 20 个 = 5 分钟以上）。
	// 这里按「同一 IP 的轮次串行、不同 IP 并发」执行，窗口语义不变，
	// 但整体耗时从 O(n) 降到 O(n/并发)。并发数取 min(4, routines/16)，
	// 太高会互相抢带宽把测速结果压低。
	conc := cfg.Routines / 16
	if conc < 1 {
		conc = 1
	}
	if conc > 4 {
		conc = 4
	}
	if conc > len(pool) {
		conc = len(pool)
	}

	var done int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxInt(1, conc))
	for _, item := range pool {
		if r.stopped() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it *Result) {
			defer wg.Done()
			defer func() { <-sem }()
			speeds := make([]float64, 0, rounds)
			for k := 0; k < rounds; k++ {
				if r.stopped() {
					break
				}
				bps, colo, ok := DownloadRound(it.IP, pu, window, timeout)
				if ok && colo != "" && it.Colo == "" {
					it.Colo = colo
					r.colo.Set(it.IP, colo)
				}
				if ok && bps > 0 {
					speeds = append(speeds, bps)
				}
				if gap > 0 && k+1 < rounds {
					time.Sleep(gap)
				}
			}
			if mean, sigma, hasSigma, ok := MeanSigma(speeds); ok {
				it.SpeedKBps = F(mean / 1024.0)
				if hasSigma {
					it.SpeedSigma = F(sigma / 1024.0)
				}
			}
			it.SpeedOK = len(speeds)
			it.SpeedRounds = rounds
			cur := int(atomic.AddInt64(&done, 1))
			r.progress("download", "下载测速中", cur, len(pool), it.IP)
		}(item)
	}
	wg.Wait()

	if dl.MinSpeedKBps > 0 {
		before := len(pool)
		kept := make([]*Result, 0, len(pool))
		for _, x := range pool {
			if x.SpeedKBps != nil && *x.SpeedKBps >= dl.MinSpeedKBps {
				kept = append(kept, x)
			}
		}
		pool = kept
		if len(pool) < before {
			r.OnLog(fmt.Sprintf("[4/5] 按速度下限 %g KB/s 过滤掉 %d 个",
				dl.MinSpeedKBps, before-len(pool)))
		}
	}

	// 结果按实测带宽降序（拿不到速度的按延迟升序垫底）。
	// 这样页面/导出/写 DNS 的顺序与「带宽最大者第一」完全一致。
	SortBySpeed(pool)
	if len(pool) > 0 {
		var parts []string
		for _, x := range pool {
			if !IsV6(x.IP) && x.SpeedKBps != nil {
				parts = append(parts, fmt.Sprintf("IPv4 最快 %s %.1f KB/s", x.IP, *x.SpeedKBps))
				break
			}
		}
		for _, x := range pool {
			if IsV6(x.IP) && x.SpeedKBps != nil {
				parts = append(parts, fmt.Sprintf("IPv6 最快 %s %.1f KB/s", x.IP, *x.SpeedKBps))
				break
			}
		}
		if len(parts) > 0 {
			r.OnLog("[4/5] " + strings.Join(parts, " · "))
		}
		if w := Best(pool); w != nil && w.SpeedKBps != nil {
			colo := w.Colo
			if colo == "" {
				colo = "---"
			}
			r.OnLog(fmt.Sprintf("[4/5] 本轮最优（带宽最大）：%s（%s）%.1f KB/s",
				w.IP, colo, *w.SpeedKBps))
		}
	}
	return pool
}

// ---------------------------------------------------------------- 地区库

// ColoDB IP → 节点代码 的学习式缓存（IPv4 按 /24、IPv6 按 /64 聚合）。
type ColoDB struct {
	path  string
	mu    sync.RWMutex
	data  map[string]string
	dirty bool
}

func NewColoDB(path string) *ColoDB {
	return &ColoDB{path: path, data: make(map[string]string, 1024)}
}

func (d *ColoDB) Get(ip string) string {
	k := BlockKey(ParseIP(ip))
	if k == "" {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.data[k]
}

func (d *ColoDB) Set(ip, colo string) bool {
	if colo == "" {
		return false
	}
	k := BlockKey(ParseIP(ip))
	if k == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data[k] == colo {
		return false
	}
	d.data[k] = colo
	d.dirty = true
	return true
}

func (d *ColoDB) Load() {
	if d.path == "" {
		return
	}
	b, err := os.ReadFile(d.path)
	if err != nil {
		return
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return
	}
	d.mu.Lock()
	d.data = m
	d.mu.Unlock()
}

func (d *ColoDB) Save() {
	if d.path == "" {
		return
	}
	d.mu.Lock()
	if !d.dirty {
		d.mu.Unlock()
		return
	}
	snapshot := make(map[string]string, len(d.data))
	for k, v := range d.data {
		snapshot[k] = v
	}
	d.dirty = false
	d.mu.Unlock()

	b, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, d.path)
}

func (d *ColoDB) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.data)
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
