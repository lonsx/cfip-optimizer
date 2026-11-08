package server

// 定时测速调度。
//
// 语义对齐原应用 cf-dns-select 的两个配置项：
//   - interval_minutes：每隔 N 分钟自动跑一轮，0 = 关闭；
//   - run_on_start    ：应用启动后立即跑一轮。
//
// 为什么不用 time.Ticker：
//   1) ticker 无法在运行期改间隔——用户在 UI 上把间隔从 60 改成 120，
//      ticker 得整个重建，容易出竞态；这里用「算下次时间点 + 可中断 sleep」，
//      每轮都重新读配置，改完立即生效；
//   2) ticker 会积压：如果某一轮跑了 40 分钟而间隔是 30 分钟，ticker 会把
//      错过的 tick 排队补跑，形成连环触发。这里用 lastRun 时间戳推算下次触发点，
//      错过的直接跳过，绝不补跑。
//
// 与「可达性守护」的分工：
//   - 定时任务（本文件）：按固定间隔做全量重测，目的是「定期找更好的 IP」；
//   - 可达性守护（guardLoop）：每分钟探测当前最优 IP 是否还活着，挂了才触发重测，
//     目的是「故障快速恢复」。
//   两者互不替代：只有定时没有守护，IP 挂了要等下一个周期；只有守护没有定时，
//   网络变好了也不会主动去换更快的 IP。

import (
	"fmt"
	"time"

	"cfip-opt/internal/engine"
)

// startScheduler 启动定时任务协程。New() 里调用一次。
func (a *App) startScheduler() {
	a.schedOnce.Do(func() {
		go a.schedLoop()
	})
}

// schedLoop 定时任务主循环。
func (a *App) schedLoop() {
	cfg := a.Store.Load()

	// 启动即跑：先等 3 秒让 HTTP 服务和守护协程就位，避免启动瞬间抢资源
	if cfg.RunOnStart {
		a.log("[定时] 已启用「启动后立即测速」，3 秒后开跑")
		select {
		case <-a.schedStop:
			return
		case <-time.After(3 * time.Second):
		}
		if !a.isRunning() {
			a.Store.MarkScheduled()
			go a.runTask(cfg, "启动任务")
		}
	}

	for {
		cfg = a.Store.Load()

		iv := cfg.IntervalMinutes
		if iv <= 0 {
			// 定时关闭：每 60 秒回来看一次配置有没有被改成非 0
			if !a.sleepSched(60 * time.Second) {
				return
			}
			continue
		}

		// 算到下一个触发点还有多久
		next := a.Store.NextRunAt(time.Duration(iv) * time.Minute)
		wait := time.Until(next)
		if wait > 0 {
			if !a.sleepSched(wait) {
				return
			}
			continue
		}

		// 到点了。若上一轮还在跑就跳过（不排队、不补跑）
		if a.isRunning() {
			a.log("[定时] 到点了但上一轮仍在运行，本轮跳过")
			a.Store.MarkScheduled()
			if !a.sleepSched(10 * time.Second) {
				return
			}
			continue
		}

		a.Store.MarkScheduled()
		go a.runTask(cfg, fmt.Sprintf("定时任务 %d 分钟", iv))
		// 给 runTask 一点时间把 Running 置位，避免紧接着的下一圈又触发一次
		if !a.sleepSched(5 * time.Second) {
			return
		}
	}
}

// sleepSched 可被停止信号打断的 sleep。返回 false 表示收到停止信号。
func (a *App) sleepSched(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-a.schedStop:
		return false
	case <-t.C:
		return true
	}
}

// Stop 停止后台协程（主要用于测试与优雅退出）。
func (a *App) Stop() {
	select {
	case <-a.schedStop:
	default:
		close(a.schedStop)
	}
	select {
	case <-a.guardStop:
	default:
		close(a.guardStop)
	}
}

// SchedInfo 供 /api/state 展示调度状态。
type SchedInfo struct {
	Enabled     bool   `json:"enabled"`
	IntervalMin int    `json:"interval_minutes"`
	RunOnStart  bool   `json:"run_on_start"`
	LastRunAt   string `json:"last_run_at"`
	NextRunAt   string `json:"next_run_at"`
}

// schedInfo 组装调度状态。
func (a *App) schedInfo(cfg engine.Config) SchedInfo {
	info := SchedInfo{
		Enabled:     cfg.IntervalMinutes > 0,
		IntervalMin: cfg.IntervalMinutes,
		RunOnStart:  cfg.RunOnStart,
	}
	if info.Enabled {
		info.NextRunAt = a.Store.NextRunAt(time.Duration(cfg.IntervalMinutes) * time.Minute).
			Format("2006-01-02 15:04:05")
		last := a.Store.LastScheduledAt()
		if !last.IsZero() {
			info.LastRunAt = last.Format("2006-01-02 15:04:05")
		}
	}
	return info
}
