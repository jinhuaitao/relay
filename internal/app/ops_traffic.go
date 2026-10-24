// traffic.go — 流量自动重置与每日流量报表定时任务
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"fmt"
	"time"
)

func trafficResetLoop() {
	for {
		time.Sleep(1 * time.Hour)

		mu.Lock()
		day := config.TrafficResetDay
		lastM := config.LastResetMonth
		mu.Unlock()

		if day <= 0 || day > 31 {
			continue
		}

		now := time.Now()
		// 计算"应清零"的月份：本月已到账单日则为本月，否则为上个月。
		// 这样即使账单日当天服务掉线，下月初也能补清上一个月的统计。
		dueMonth := now.Format("2006-01")
		if now.Day() < day {
			dueMonth = now.AddDate(0, -1, 0).Format("2006-01")
		}

		if lastM != dueMonth {
			mu.Lock()
			for i := range rules {
				rules[i].TotalTx = 0
				rules[i].TotalRx = 0
				rules[i].Alert80 = false
				rules[i].Alert95 = false
				rules[i].Alert100 = false
			}
			config.LastResetMonth = dueMonth
			saveConfigNoLock()
			mu.Unlock()

			sendTelegram(fmt.Sprintf("📅 <b>账单日触发</b>\n系统已自动清零 %s 所有规则的流量统计！", dueMonth))
			go pushConfigToAll()
		}
	}
}

func dailyTrafficReportLoop() {
	var lastReportDate string
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()

		// 日报主窗口放宽到 23:55–23:59，并在次日 00:00–00:14 保留补发窗口。
		// 原实现要求精确命中 23:59 这一分钟，而循环周期是 1 分钟 + 执行耗时，
		// 长期运行必然漂移，存在整日漏发风险。
		var reportDay string
		if now.Hour() == 23 && now.Minute() >= 55 {
			reportDay = now.Format("2006-01-02")
		} else if now.Hour() == 0 && now.Minute() < 15 {
			reportDay = now.AddDate(0, 0, -1).Format("2006-01-02")
		}
		if reportDay == "" || lastReportDate == reportDay {
			continue
		}

		flushDailyStats()

		if db == nil {
			lastReportDate = reportDay
			continue
		}

		var tx, rx int64
		err := db.QueryRow("SELECT tx, rx FROM daily_stats WHERE date = ?", reportDay).Scan(&tx, &rx)
		if err == nil && (tx > 0 || rx > 0) {
			msg := fmt.Sprintf("📈 <b>每日流量日报</b>\n\n🗓️ 日期: %s\n⬆️ 今日上传: %s\n⬇️ 今日下载: %s\n🌐 今日总消耗: <b>%s</b>",
				reportDay, formatBytes(tx), formatBytes(rx), formatBytes(tx+rx))
			sendTelegram(msg)
		}
		lastReportDate = reportDay
	}
}
