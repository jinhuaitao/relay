// handlers_settings.go — 系统设置、配置导入导出、日志与规则导出
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	mu.Lock()
	oldPanelDomain := config.PanelDomain
	oldMasterDomain := config.MasterDomain
	oldPorts := config.AgentPorts

	if p := r.FormValue("password"); p != "" {
		salt := generateSalt()
		config.WebPass = salt + "$" + hashPassword(p, salt)
	}
	config.AgentPorts = r.FormValue("agent_ports")
	config.MasterDomain = r.FormValue("master_domain")
	config.PanelDomain = r.FormValue("panel_domain")
	// TG 凭证必须清洗首尾空白：带空格的 Chat ID 会导致所有身份校验恒不相等，
	// 表现为机器人"完全不响应"
	config.TgBotToken = strings.TrimSpace(r.FormValue("tg_bot_token"))
	config.TgChatID = strings.TrimSpace(r.FormValue("tg_chat_id"))
	config.GithubClientID = r.FormValue("github_client_id")
	config.GithubClientSecret = r.FormValue("github_client_secret")
	config.GithubAllowedUsers = r.FormValue("github_allowed_users")
	config.R2AccessKey = r.FormValue("r2_access_key")
	config.R2SecretKey = r.FormValue("r2_secret_key")
	config.R2Endpoint = r.FormValue("r2_endpoint")
	config.R2Bucket = r.FormValue("r2_bucket")

	if rd := r.FormValue("traffic_reset_day"); rd != "" {
		d, _ := strconv.Atoi(rd)
		if d < 0 || d > 31 {
			d = 0
		}
		config.TrafficResetDay = d
	} else {
		config.TrafficResetDay = 0
	}

	saveConfigNoLock()

	newPanelDomain := config.PanelDomain
	newMasterDomain := config.MasterDomain
	newPorts := config.AgentPorts
	mu.Unlock()

	needRestart := (oldPanelDomain != newPanelDomain) || (oldMasterDomain != newMasterDomain) || (oldPorts != newPorts)

	addLog(r, "修改配置", "更新了系统全局配置")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"need_restart":  needRestart,
		"redirect_host": newPanelDomain,
	})

	if needRestart {
		go func() {
			time.Sleep(1 * time.Second)
			doRestart()
		}()
	}
}

func handleDownloadConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=data.db")
	http.ServeFile(w, r, DBFile)
}

func handleUploadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	file, _, err := r.FormFile("db_file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "读取上传文件失败"})
		return
	}
	defer file.Close()

	// 1. 获取锁，安全地清理旧数据库连接
	mu.Lock()

	if db != nil {
		db.Close()
		db = nil
	}

	os.Remove(DBFile + "-wal")
	os.Remove(DBFile + "-shm")

	out, err := os.Create(DBFile)
	if err != nil {
		// 恢复数据库连接，避免面板进入 db=nil 半瘫态
		initDB()
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "无法覆盖写入新文件"})
		return
	}

	// 2. 覆盖写入新数据
	io.Copy(out, file)
	out.Close() // 必须显式关闭文件句柄

	// 3. 重新初始化数据库连接
	initDB()

	// 4. 解锁！必须在 loadConfig 之前解锁，避免内部循环锁死锁
	mu.Unlock()

	// 5. 将新数据库中的配置重新加载到内存中
	loadConfig()

	// 获取恢复后的新面板域名
	mu.Lock()
	newPanelDomain := config.PanelDomain
	mu.Unlock()

	// 6. 响应前端成功，并下发新的重定向域名
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"redirect_host": newPanelDomain,
	})
}

func handleExportLogs(w http.ResponseWriter, r *http.Request) {
	var logs []OpLog
	if db != nil {
		rows, err := db.Query("SELECT time, ip, COALESCE(category,'') AS category, action, msg FROM logs ORDER BY id DESC")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l OpLog
				rows.Scan(&l.Time, &l.IP, &l.Category, &l.Action, &l.Msg)
				logs = append(logs, l)
			}
		}
	}
	b, _ := json.MarshalIndent(logs, "", "  ")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
	w.Write(b)
}

func handleClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	if db != nil {
		// 清空 logs 表
		_, err := db.Exec("DELETE FROM logs")
		if err == nil {
			// 重置自增 ID (SQLite 特定语法)
			db.Exec("DELETE FROM sqlite_sequence WHERE name='logs'")
			// 添加一条清空操作的记录
			addLog(r, "清理日志", "管理员手动清空了所有操作日志")
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleExportRules(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=rules_backup.json")
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func handleImportRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	file, _, err := r.FormFile("rules_file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "读取上传文件失败"})
		return
	}
	defer file.Close()

	var importedRules []LogicalRule
	if err := json.NewDecoder(file).Decode(&importedRules); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "解析 JSON 格式失败，请确保文件正确"})
		return
	}

	mu.Lock()
	rules = importedRules
	saveConfigNoLock()
	mu.Unlock()

	go pushConfigToAll()

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	addLog(r, "重启服务", "管理员触发了系统重启")
	w.Write([]byte("ok"))
	go func() {
		time.Sleep(500 * time.Millisecond)
		doRestart()
	}()
}
