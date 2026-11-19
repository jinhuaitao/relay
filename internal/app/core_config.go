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

	// 首次初始化令牌：仅在尚未完成 setup 时生成。
	// 远程访问 /setup 必须携带它，避免部署窗口期被端口扫描器抢先设置管理员。
	if !config.IsSetup && setupToken == "" {
		setupToken = generateSalt()[:16]
		log.Printf("🔐 初始化令牌: %s", setupToken)
		log.Printf("   首次部署请用本机访问 http://127.0.0.1%s/setup 直接初始化；", WebPort)
		log.Printf("   从远程访问 /setup 时必须填写上面这串令牌（重启会重新生成）")
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

// saveConfig 由流量脏标记定时触发：只更新流量与告警列。
// 结构性变更（增删改规则、启停）由各 handler 即时单行持久化，
// 不再每 30 秒全表 DELETE + 重插。
func saveConfig() {
	mu.Lock()
	defer mu.Unlock()
	for _, r := range rules {
		_, _ = db.Exec("UPDATE rules SET total_tx=?, total_rx=?, alert_80=?, alert_95=?, alert_100=? WHERE id=?",
			r.TotalTx, r.TotalRx, b2i(r.Alert80), b2i(r.Alert95), b2i(r.Alert100), r.ID)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

const ruleUpsertSQL = `INSERT OR REPLACE INTO rules (id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx, lb_strategy, alert_80, alert_95, alert_100) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

func ruleArgs(r LogicalRule) []interface{} {
	return []interface{}{
		r.ID, r.Group, r.Note, r.EntryAgent, r.EntryPort, r.ExitAgent, r.TargetIP, r.TargetPort,
		r.Protocol, r.BridgePort, r.TrafficLimit, b2i(r.Disabled), r.SpeedLimit, r.TotalTx, r.TotalRx,
		r.LBStrategy, b2i(r.Alert80), b2i(r.Alert95), b2i(r.Alert100),
	}
}

// upsertRuleNoLock 单行持久化一条规则。调用方必须持有 mu。
func upsertRuleNoLock(r LogicalRule) {
	_, _ = db.Exec(ruleUpsertSQL, ruleArgs(r)...)
}

// deleteRuleRowNoLock 单行删除一条规则。调用方必须持有 mu。
func deleteRuleRowNoLock(id string) {
	_, _ = db.Exec("DELETE FROM rules WHERE id = ?", id)
}

// saveSettingsNoLock 仅持久化 settings 表（口令、域名、TG/R2 凭证等）。
// 调用方必须持有 mu。
func saveSettingsNoLock() {
	conf := config
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
	_ = tx.Commit()
}

// saveConfigNoLock 全量落盘（settings + 规则集合）。
// 用于关机、导入覆盖、月度清零等低频场景；用 upsert + 清理失效 ID
// 替代旧的 DELETE FROM rules 全表重插。调用方必须持有 mu。
func saveConfigNoLock() {
	saveSettingsNoLock()

	lRules := make([]LogicalRule, len(rules))
	copy(lRules, rules)

	tx, _ := db.Begin()
	for _, r := range lRules {
		_, _ = tx.Exec(ruleUpsertSQL, ruleArgs(r)...)
	}
	if len(lRules) == 0 {
		_, _ = tx.Exec("DELETE FROM rules")
	} else {
		ids := make([]interface{}, len(lRules))
		for i, r := range lRules {
			ids[i] = r.ID
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(lRules)), ",")
		_, _ = tx.Exec("DELETE FROM rules WHERE id NOT IN ("+placeholders+")", ids...)
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
