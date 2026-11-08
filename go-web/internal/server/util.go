package server

import (
	"os"
	"sync/atomic"
)

// 守护流程用到的两个时间戳，用原子变量避免给 App 结构体到处加锁。
var (
	lastRerunTS   int64 // 上次自动重测的 unix 时间
	lastRefreshTS int64 // 上次定时刷新的 unix 时间
)

func init() {
	atomic.StoreInt64(&lastRerunTS, 0)
	atomic.StoreInt64(&lastRefreshTS, 0)
}

// 文件读写小工具（原子替换依赖 rename）。
func readFile(p string) ([]byte, error)  { return os.ReadFile(p) }
func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o644) }
func rename(a, b string) error           { return os.Rename(a, b) }
