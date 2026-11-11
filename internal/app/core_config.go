// config.go — 配置持久化：加载/保存、日志清理、离线节点回收
//
// 保存路径现在会检查事务与每条语句的错误：旧实现把所有错误吞掉，
// 一旦磁盘满或表结构异常，规则会静默丢失而面板毫无提示。

package app

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"
)

func loadConfig() {
	mu.Lock()
	defer mu.Unlock()
	rows, err := db.Query("SELECT key, value FROM settings")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				continue
			}
			switch k {
			case "web_user":
				config.WebUser = v
			case "web_pass":
				config.WebPass = v
			case "agent_token":
				config.AgentToken = v
			case "agent_tokens":
				_ = json.Unmarshal([]byte(v), &config.AgentTokens)
			case "agent_add_times":
				_ = json.Unmarshal([]byte(v), &config.AgentAddTimes)
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
			case "backup_passphrase":
				config.BackupPassphrase = v
			case "trusted_proxies":
				config.TrustedProxies = v
			}
		}
	}

	if config.AgentTokens == nil {
		config.AgentTokens = make(map[string]string)
	}
	setTrustedProxies(config.TrustedProxies)

	lastTgBackupDate = ""
	if err := db.QueryRow("SELECT value FROM settings WHERE key = 'last_backup_date'").Scan(&lastTgBackupDate); err != nil {
		lastTgBackupDate = ""
	}

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
			if err := rRows.Scan(&r.ID, &r.Group, &r.Note, &r.EntryAgent, &r.EntryPort, &r.ExitAgent, &r.TargetIP, &r.TargetPort, &r.Protocol, &r.BridgePort, &r.TrafficLimit, &d, &r.SpeedLimit, &r.TotalTx, &r.TotalRx, &r.LBStrategy, &a80, &a95, &a100); err != nil {
				log.Printf("⚠️ 读取规则行失败，已跳过: %v", err)
				continue
			}
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

// saveConfigNoLock 必须在调用方持有 mu 时使用。
func saveConfigNoLock() {
	if db == nil {
		log.Printf("⚠️ 保存配置失败：数据库未初始化")
		return
	}
	conf := config
	lRules := make([]LogicalRule, len(rules))
	copy(lRules, rules)

	tx, err := db.Begin()
	if err != nil {
		log.Printf("⚠️ 保存配置失败（开启事务）: %v", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var saveErr error
	setS := func(k, v string) {
		if saveErr != nil {
			return
		}
		if _, e := tx.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", k, v); e != nil {
			saveErr = e
		}
	}
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
	setS("backup_passphrase", conf.BackupPassphrase)
	setS("trusted_proxies", conf.TrustedProxies)

	if saveErr == nil {
		_, saveErr = tx.Exec("DELETE FROM rules")
	}
	for _, r := range lRules {
		if saveErr != nil {
			break
		}
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
		_, saveErr = tx.Exec(`INSERT INTO rules (id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx, lb_strategy, alert_80, alert_95, alert_100) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Group, r.Note, r.EntryAgent, r.EntryPort, r.ExitAgent, r.TargetIP, r.TargetPort, r.Protocol, r.BridgePort, r.TrafficLimit, d, r.SpeedLimit, r.TotalTx, r.TotalRx, r.LBStrategy, a80, a95, a100)
	}
	if saveErr != nil {
		log.Printf("⚠️ 保存配置失败（写入）: %v", saveErr)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("⚠️ 保存配置失败（提交）: %v", err)
		return
	}
	committed = true
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

// cleanExpiredSessions 回收过期会话与 OAuth state，避免内存无界增长。
func cleanExpiredSessions() {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	for sid, exp := range sessions {
		if now.After(exp) {
			delete(sessions, sid)
		}
	}
	for state, exp := range oauthStates {
		if now.After(exp) {
			delete(oauthStates, state)
		}
	}
	loginAttempts.Range(func(k, _ interface{}) bool {
		if t, ok := blockUntil.Load(k); ok && now.After(t.(time.Time)) {
			blockUntil.Delete(k)
			loginAttempts.Delete(k)
		}
		return true
	})
}

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
