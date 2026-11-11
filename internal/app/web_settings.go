// handlers_settings.go — 系统设置、配置导入导出、日志与规则导出
//
// 加固点：密钥类设置项不再回显，留空保持原值（__CLEAR__ 显式清空）；
// 上传数据库前做大小、SQLite 魔数与核心表校验，并保留可回滚的备份。

package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// applySecretField 实现「留空保持不变」，避免面板刷新把已保存的密钥清空。
func applySecretField(current, submitted string) string {
	if submitted == "" {
		return current
	}
	if submitted == clearSentinel {
		return ""
	}
	return submitted
}

func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	mu.Lock()
	oldPanelDomain := config.PanelDomain
	oldMasterDomain := config.MasterDomain
	oldPorts := config.AgentPorts

	if p := r.FormValue("password"); p != "" {
		pwdHash, err := hashNewPassword(p)
		if err != nil {
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "口令散列失败"})
			return
		}
		config.WebPass = pwdHash
	}
	config.AgentPorts = r.FormValue("agent_ports")
	config.MasterDomain = r.FormValue("master_domain")
	config.PanelDomain = r.FormValue("panel_domain")
	config.TgBotToken = strings.TrimSpace(applySecretField(config.TgBotToken, r.FormValue("tg_bot_token")))
	config.TgChatID = strings.TrimSpace(r.FormValue("tg_chat_id"))
	config.GithubClientID = r.FormValue("github_client_id")
	config.GithubClientSecret = applySecretField(config.GithubClientSecret, r.FormValue("github_client_secret"))
	config.GithubAllowedUsers = r.FormValue("github_allowed_users")
	config.R2AccessKey = applySecretField(config.R2AccessKey, r.FormValue("r2_access_key"))
	config.R2SecretKey = applySecretField(config.R2SecretKey, r.FormValue("r2_secret_key"))
	config.R2Endpoint = r.FormValue("r2_endpoint")
	config.R2Bucket = r.FormValue("r2_bucket")
	config.BackupPassphrase = applySecretField(config.BackupPassphrase, r.FormValue("backup_passphrase"))
	config.TrustedProxies = r.FormValue("trusted_proxies")

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
	trusted := config.TrustedProxies
	mu.Unlock()
	setTrustedProxies(trusted)

	needRestart := (oldPanelDomain != newPanelDomain) || (oldMasterDomain != newMasterDomain) || (oldPorts != newPorts)
	addLog(r, "修改配置", "更新了系统全局配置")

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

// snapshotDB 生成一份内容一致、可直接打开的数据库快照。
func snapshotDB() (string, error) {
	mu.Lock()
	d := db
	mu.Unlock()
	if d == nil {
		return "", fmt.Errorf("数据库尚未初始化")
	}

	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("gorelay_snapshot_%d.db", time.Now().UnixNano()))
	_ = os.Remove(tmp)

	if _, err := d.Exec("VACUUM INTO ?", tmp); err == nil {
		if fi, serr := os.Stat(tmp); serr == nil && fi.Size() > 0 {
			return tmp, nil
		}
		_ = os.Remove(tmp)
	}

	_, _ = d.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	if err := copyFile(DBFile, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// verifySQLiteDB 校验文件确实是可打开的 SQLite 库，且包含核心表。
func verifySQLiteDB(path string) error {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer d.Close()
	var n int
	if err := d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('settings','rules')").Scan(&n); err != nil {
		return fmt.Errorf("不是有效的 GoRelay 数据库: %w", err)
	}
	if n < 2 {
		return fmt.Errorf("备份文件缺少 settings / rules 表")
	}
	return nil
}

func handleDownloadConfig(w http.ResponseWriter, r *http.Request) {
	tmp, err := snapshotDB()
	if err != nil {
		addLog(r, "导出配置", "生成数据库快照失败: "+err.Error())
		http.Error(w, "生成备份失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp)

	name := fmt.Sprintf("gorelay_backup_%s.db", time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, tmp)
	addLog(r, "导出配置", "已导出完整数据库快照（含凭据，请妥善保管）")
}

func handleUploadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	respond := func(ok bool, msg string) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": ok, "error": msg})
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)
	file, _, err := r.FormFile("db_file")
	if err != nil {
		respond(false, "读取上传文件失败（文件或请求体过大）")
		return
	}
	defer file.Close()

	buf, err := io.ReadAll(io.LimitReader(file, MaxUploadSize+1))
	if err != nil || len(buf) > MaxUploadSize {
		respond(false, "备份文件超过 64MB 上限")
		return
	}
	if len(buf) < 100 || !bytes.Equal(buf[:16], []byte("SQLite format 3\x00")) {
		respond(false, "不是有效的 SQLite 数据库文件")
		return
	}

	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("gorelay_upload_%d.db", time.Now().UnixNano()))
	if err := os.WriteFile(tmp, buf, 0600); err != nil {
		respond(false, "写入临时文件失败")
		return
	}
	defer os.Remove(tmp)
	if err := verifySQLiteDB(tmp); err != nil {
		respond(false, err.Error())
		return
	}

	// 覆盖前留一份一致性快照，任何一步失败都能回滚
	backupPath := ""
	if snap, e := snapshotDB(); e == nil {
		backupPath = snap
	}
	defer func() {
		if backupPath != "" {
			_ = os.Remove(backupPath)
		}
	}()

	mu.Lock()
	if db != nil {
		_ = db.Close()
		db = nil
	}
	_ = os.Remove(DBFile + "-wal")
	_ = os.Remove(DBFile + "-shm")
	if err := copyFile(tmp, DBFile); err != nil {
		if backupPath != "" {
			_ = copyFile(backupPath, DBFile)
		}
		initDB()
		mu.Unlock()
		respond(false, "无法覆盖写入新数据库：已回滚")
		return
	}
	initDB()
	mu.Unlock()

	loadConfig()

	mu.Lock()
	newPanelDomain := config.PanelDomain
	mu.Unlock()

	addLog(r, "恢复配置", "已从上传的数据库恢复配置")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"redirect_host": newPanelDomain,
	})
}

func handleExportLogs(w http.ResponseWriter, r *http.Request) {
	var logs []OpLog
	if db != nil {
		rows, err := db.Query("SELECT time, ip, COALESCE(category,'') AS category, action, msg FROM logs ORDER BY id DESC LIMIT 10000")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l OpLog
				if err := rows.Scan(&l.Time, &l.IP, &l.Category, &l.Action, &l.Msg); err == nil {
					logs = append(logs, l)
				}
			}
		}
	}
	b, _ := json.MarshalIndent(logs, "", "  ")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func handleClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if db != nil {
		if _, err := db.Exec("DELETE FROM logs"); err == nil {
			_, _ = db.Exec("DELETE FROM sqlite_sequence WHERE name='logs'")
			addLog(r, "清理日志", "管理员手动清空了所有操作日志")
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleExportRules(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	b, err := json.MarshalIndent(rules, "", "  ")
	mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=rules_backup.json")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func handleImportRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	file, _, err := r.FormFile("rules_file")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "读取上传文件失败"})
		return
	}
	defer file.Close()

	var imported []LogicalRule
	if err := json.NewDecoder(io.LimitReader(file, 8<<20)).Decode(&imported); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "解析 JSON 格式失败，请确保文件正确"})
		return
	}
	validated, err := validateImportedRules(imported)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	mu.Lock()
	rules = validated
	saveConfigNoLock()
	mu.Unlock()

	go pushConfigToAll()
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	addLog(r, "重启服务", "管理员触发了系统重启")
	_, _ = w.Write([]byte("ok"))
	go func() {
		time.Sleep(500 * time.Millisecond)
		doRestart()
	}()
}
