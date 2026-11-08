package engine

import (
	"fmt"
	"strings"
)

// FormatLine 按固定列宽输出一行：
//
//	104.17.96.0     HKG  234.8ms  σ=13.6   (6/6)   843.8 KB/s  σ=271.2 (3/3)
func FormatLine(r *Result) string {
	ip := r.IP
	for len(ip) < 15 {
		ip += " "
	}
	colo := r.Colo
	if colo == "" {
		colo = "---"
	}
	if len(colo) > 3 {
		colo = colo[:3]
	}
	for len(colo) < 3 {
		colo += " "
	}

	delay := "-"
	if r.DelayMS != nil {
		delay = fmt.Sprintf("%.1fms", *r.DelayMS)
	}
	dtxt := "     σ=-"
	if r.DelaySigma != nil {
		dtxt = fmt.Sprintf("  σ=%.1f", *r.DelaySigma)
	}
	dcount := fmt.Sprintf("(%d/%d)", r.DelayOK, r.DelayRounds)
	for len(dcount) < 6 {
		dcount += " "
	}

	stxt := "         -"
	sstxt := "     σ=-"
	if r.SpeedKBps != nil {
		stxt = fmt.Sprintf("%8.1f KB/s", *r.SpeedKBps)
		if r.SpeedSigma != nil {
			sstxt = fmt.Sprintf("  σ=%.1f", *r.SpeedSigma)
		}
	}
	scount := fmt.Sprintf("(%d/%d)", r.SpeedOK, r.SpeedRounds)

	return fmt.Sprintf("%s %s %8s %s %s  %s %s %s",
		ip, colo, delay, dtxt, dcount, stxt, sstxt, scount)
}

// FormatText 纯文本导出。
func FormatText(rows []*Result) string {
	var sb strings.Builder
	for i, r := range rows {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(FormatLine(r))
	}
	return sb.String()
}

// FormatCSV CSV 导出，列与 Python 版一致。
func FormatCSV(rows []*Result) string {
	var sb strings.Builder
	sb.WriteString("ip,colo,delay_ms,delay_sigma,delay_ok,delay_rounds,")
	sb.WriteString("speed_kbps,speed_sigma,speed_ok,speed_rounds,loss_rate\n")
	for _, r := range rows {
		sb.WriteString(r.IP)
		sb.WriteString(",")
		sb.WriteString(r.Colo)
		sb.WriteString(",")
		sb.WriteString(fmtF(r.DelayMS))
		sb.WriteString(",")
		sb.WriteString(fmtF(r.DelaySigma))
		sb.WriteString(",")
		sb.WriteString(fmt.Sprintf("%d", r.DelayOK))
		sb.WriteString(",")
		sb.WriteString(fmt.Sprintf("%d", r.DelayRounds))
		sb.WriteString(",")
		sb.WriteString(fmtF(r.SpeedKBps))
		sb.WriteString(",")
		sb.WriteString(fmtF(r.SpeedSigma))
		sb.WriteString(",")
		sb.WriteString(fmt.Sprintf("%d", r.SpeedOK))
		sb.WriteString(",")
		sb.WriteString(fmt.Sprintf("%d", r.SpeedRounds))
		sb.WriteString(",")
		sb.WriteString(fmt.Sprintf("%.2f", r.LossRate))
		sb.WriteString("\n")
	}
	return sb.String()
}

func fmtF(v *float64) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%.2f", *v)
}
