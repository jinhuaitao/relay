// config.go — 配置持久化：加载/保存、日志清理、离线节点回收
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
)

func loadConfig() {
	mu.Lock()
	defer mu.Unlock()
	rows, err := db.Query("SELECT key, value FROM settings")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			rows.Scan(&k, &v)
			switch k {
			case "web_user":
				config.WebUser = v
			case "web_pass":
				config.WebPass = v
			case "agent_token":
				config.AgentToken = v
			case "agent_tokens":
				json.Unmarshal([]byte(v), &config.AgentTokens)
			case "agent_add_times":
				json.Unmarshal([]byte(v), &config.AgentAddTimes)
			case "agent_ports":
				config.AgentPorts = v
			case "master_domain":
				config.MasterDomain = v
			case "panel_domain":
				config.PanelDomain = v
			case "is_setup":
				config.IsSetup = (v == "true")
			case "tg_bot_token":
				config.TgBotToken = strings.TrimSpace(v)
			case "tg_chat_id":
				config.TgChatID = strings.TrimSpace(v)
			case "two_fa_enabled":
				config.TwoFAEnabled = (v == "true")
			case "two_fa_secret":
				config.TwoFASecret = v
			case "github_client_id":
				config.GithubClientID = v
			case "github_client_secret":
				config.GithubClientSecret = v
			case "github_allowed_users":
				config.GithubAllowedUsers = v
			case "traffic_reset_day":
				d, _ := strconv.Atoi(v)
				config.TrafficResetDay = d
			case "last_reset_month":
				config.LastResetMonth = v
			case "r2_access_key":
				config.R2AccessKey = v
			case "r2_secret_key":
				config.R2SecretKey = v
			case "r2_endpoint":
				config.R2Endpoint = v
			case "r2_bucket":
				config.R2Bucket = v
			}
		}
	}

	if config.AgentTokens == nil {
		config.AgentTokens = make(map[string]string)
	}

	// 恢复 TG 周备份幂等键，保证进程重启后不会在同一周重复备份
	lastTgBackupDate = ""
	if err := db.QueryRow("SELECT value FROM settings WHERE key = 'last_backup_date'").Scan(&lastTgBackupDate); err != nil {
		lastTgBackupDate = ""
	}

	rules = []LogicalRule{}
	rRows, err := db.Query("SELECT id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx, lb_strategy, alert_80, alert_95, alert_100 FROM rules")
	if err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var r LogicalRule
			var d, a80, a95, a100 int
			rRows.Scan(&r.ID, &r.Group, &r.Note, &r.EntryAgent, &r.EntryPort, &r.ExitAgent, &r.TargetIP, &r.TargetPort, &r.Protocol, &r.BridgePort, &r.TrafficLimit, &d, &r.SpeedLimit, &r.TotalTx, &r.TotalRx, &r.LBStrategy, &a80, &a95, &a100)
			r.Disabled = (d == 1)
			r.Alert80 = (a80 == 1)
			r.Alert95 = (a95 == 1)
			r.Alert100 = (a100 == 1)
			rules = append(rules, r)
		}
	}
}

func saveConfig() {
	mu.Lock()
	defer mu.Unlock()
	saveConfigNoLock()
}

func saveConfigNoLock() {
	conf := config
	lRules := make([]LogicalRule, len(rules))
	copy(lRules, rules)

	tx, _ := db.Begin()
	setS := func(k, v string) { _, _ = tx.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", k, v) }
	setS("web_user", conf.WebUser)
	setS("web_pass", conf.WebPass)
	setS("agent_token", conf.AgentToken)
	if conf.AgentTokens != nil {
		b, _ := json.Marshal(conf.AgentTokens)
		setS("agent_tokens", string(b))
	}
	if conf.AgentAddTimes != nil {
		b, _ := json.Marshal(conf.AgentAddTimes)
		setS("agent_add_times", string(b))
	}
	setS("agent_ports", conf.AgentPorts)
	setS("master_domain", conf.MasterDomain)
	setS("panel_domain", conf.PanelDomain)
	setS("is_setup", strconv.FormatBool(conf.IsSetup))
	setS("tg_bot_token", conf.TgBotToken)
	setS("tg_chat_id", conf.TgChatID)
	setS("two_fa_enabled", strconv.FormatBool(conf.TwoFAEnabled))
	setS("two_fa_secret", conf.TwoFASecret)
	setS("github_client_id", conf.GithubClientID)
	setS("github_client_secret", conf.GithubClientSecret)
	setS("github_allowed_users", conf.GithubAllowedUsers)
	setS("traffic_reset_day", strconv.Itoa(conf.TrafficResetDay))
	setS("last_reset_month", conf.LastResetMonth)
	setS("r2_access_key", conf.R2AccessKey)
	setS("r2_secret_key", conf.R2SecretKey)
	setS("r2_endpoint", conf.R2Endpoint)
	setS("r2_bucket", conf.R2Bucket)

	_, _ = tx.Exec("DELETE FROM rules")
	for _, r := range lRules {
		d, a80, a95, a100 := 0, 0, 0, 0
		if r.Disabled {
			d = 1
		}
		if r.Alert80 {
			a80 = 1
		}
		if r.Alert95 {
			a95 = 1
		}
		if r.Alert100 {
			a100 = 1
		}

		_, _ = tx.Exec(`INSERT INTO rules (id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx, lb_strategy, alert_80, alert_95, alert_100) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Group, r.Note, r.EntryAgent, r.EntryPort, r.ExitAgent, r.TargetIP, r.TargetPort, r.Protocol, r.BridgePort, r.TrafficLimit, d, r.SpeedLimit, r.TotalTx, r.TotalRx, r.LBStrategy, a80, a95, a100)
	}
	_ = tx.Commit()
}

func cleanOldLogs() {
	if db == nil {
		return
	}
	_, err := db.Exec("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?)", MaxLogRetention)
	if err != nil {
		log.Printf("⚠️ 清理日志失败: %v", err)
	}
}

// pruneOfflineAgents 清理离线且无规则引用的 Agent，避免 agents map 无界增长。
// 仍被规则引用的离线 Agent 保留（用于面板展示"离线"状态）。
func pruneOfflineAgents() {
	mu.Lock()
	defer mu.Unlock()
	used := make(map[string]bool)
	for _, r := range rules {
		used[r.EntryAgent] = true
		used[r.ExitAgent] = true
	}
	for name, a := range agents {
		if !a.IsOnline && !used[name] {
			delete(agents, name)
		}
	}
}
