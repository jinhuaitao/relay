// handlers_page.go — 控制面板首页渲染（注入规则、节点、日志、统计等页面数据）
//
// 注入模板前会剥离所有凭据字段：面板 DOM 里不再出现任何密钥明文，
// 即使前端存在注入点也不会造成凭据泄露。

package app

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
)

// sanitizedConfigForView 返回只含非敏感展示字段的配置副本。
func sanitizedConfigForView(in AppConfig) AppConfig {
	out := in
	out.WebPass = ""
	out.AgentToken = ""
	out.AgentTokens = nil
	out.AgentAddTimes = nil
	out.TwoFASecret = ""
	out.TgBotToken = ""
	out.GithubClientSecret = ""
	out.R2AccessKey = ""
	out.R2SecretKey = ""
	out.BackupPassphrase = ""
	out.Rules = nil
	out.Logs = nil
	return out
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	al := make([]*AgentInfo, 0)
	for _, a := range agents {
		al = append(al, a)
	}
	sort.Slice(al, func(i, j int) bool {
		t1 := config.AgentAddTimes[al[i].Name]
		t2 := config.AgentAddTimes[al[j].Name]
		if t1 == t2 {
			return al[i].Name < al[j].Name
		}
		return t1 < t2
	})
	var totalTraffic int64
	for _, r := range rules {
		totalTraffic += (r.TotalTx + r.TotalRx)
	}
	displayRules := make([]LogicalRule, len(rules))
	for i, r := range rules {
		displayRules[i] = r
		if a, ok := agents[r.EntryAgent]; ok {
			rip := a.RemoteIP
			if strings.Contains(rip, ":") && !strings.Contains(rip, "[") {
				rip = "[" + rip + "]"
			}
			displayRules[i].EntryIP = rip
		} else {
			displayRules[i].EntryIP = "离线"
		}
	}
	mu.Unlock()

	sort.Slice(displayRules, func(i, j int) bool {
		if displayRules[i].Group == displayRules[j].Group {
			return displayRules[i].ID < displayRules[j].ID
		}
		return displayRules[i].Group < displayRules[j].Group
	})

	var displayLogs []OpLog
	if db != nil {
		rows, err := db.Query("SELECT time, ip, COALESCE(category,'') AS category, action, msg FROM logs ORDER BY id DESC LIMIT ?", MaxLogEntries)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l OpLog
				if err := rows.Scan(&l.Time, &l.IP, &l.Category, &l.Action, &l.Msg); err == nil {
					displayLogs = append(displayLogs, l)
				}
			}
		}
	}

	var dailyStats []DailyStat
	if db != nil {
		dsRows, err := db.Query("SELECT date, tx, rx FROM daily_stats ORDER BY date DESC LIMIT 30")
		if err == nil {
			defer dsRows.Close()
			for dsRows.Next() {
				var ds DailyStat
				if err := dsRows.Scan(&ds.Date, &ds.Tx, &ds.Rx); err == nil {
					dailyStats = append(dailyStats, ds)
				}
			}
		}
	}
	for i, j := 0, len(dailyStats)-1; i < j; i, j = i+1, j-1 {
		dailyStats[i], dailyStats[j] = dailyStats[j], dailyStats[i]
	}
	if len(dailyStats) == 0 {
		dailyStats = append(dailyStats, DailyStat{Date: time.Now().Format("2006-01-02"), Tx: 0, Rx: 0})
	}
	dsBytes, _ := json.Marshal(dailyStats)

	mu.Lock()
	conf := sanitizedConfigForView(config)
	mu.Unlock()

	pStr := conf.AgentPorts
	if pStr == "" {
		pStr = "9999"
	}
	cleanPorts := make([]string, 0)
	for _, p := range strings.Split(pStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cleanPorts = append(cleanPorts, strings.TrimPrefix(p, ":"))
		}
	}

	data := struct {
		Agents         []*AgentInfo
		Rules          []LogicalRule
		Logs           []OpLog
		User           string
		DownloadURL    string
		TotalTraffic   int64
		MasterDomain   string
		PanelDomain    string
		Config         AppConfig
		TwoFA          bool
		IsTLS          bool
		Ports          []string
		Version        string
		DailyStatsJSON template.JS
	}{al, displayRules, displayLogs, conf.WebUser, DownloadURL, totalTraffic, conf.MasterDomain, conf.PanelDomain, conf, conf.TwoFAEnabled, isMasterTLS, cleanPorts, AppVersion, template.JS(string(dsBytes))}

	t := template.New("dash").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"add":         func(a, b int64) int64 { return a + b },
		"percent": func(currTx, currRx, limit int64) float64 {
			if limit <= 0 {
				return 0
			}
			p := (float64(currTx+currRx) / float64(limit)) * 100
			if p > 100 {
				p = 100
			}
			return p
		},
		"formatSpeed": func(bytesPerSec int64) string {
			if bytesPerSec <= 0 {
				return "无限制"
			}
			return formatBytes(bytesPerSec) + "/s"
		},
		"logCatColor": func(cat string) string {
			switch cat {
			case "login":
				return "background:#3b82f6;color:#fff"
			case "node":
				return "background:#10b981;color:#fff"
			case "rule":
				return "background:#a855f7;color:#fff"
			case "config":
				return "background:#f59e0b;color:#fff"
			default:
				return "background:#64748b;color:#fff"
			}
		},
		"logCatLabel": func(cat string) string {
			switch cat {
			case "login":
				return "登录"
			case "node":
				return "节点"
			case "rule":
				return "规则"
			case "config":
				return "配置"
			default:
				return "系统"
			}
		},
	})
	t, _ = t.Parse(dashboardHtml)
	_ = t.Execute(w, data)
}
