// backup_crypto.go — 云备份生成与离线解密
//
// 所有外发备份（Telegram / R2）都必须走这里：
//   1. VACUUM INTO 生成一致性快照
//   2. 从快照中删除全部凭据类 settings，并 VACUUM 压实，避免被删页残留
//   3. 用面板配置的备份口令做 AES-256-GCM 加密
// 未配置口令时直接拒绝外发，绝不回退成明文。

package app

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sensitiveSettingKeys 是会写入 data.db 的全部密钥/凭据字段。
var sensitiveSettingKeys = []string{
	"web_pass", "agent_token", "agent_tokens", "two_fa_secret",
	"tg_bot_token", "github_client_secret", "r2_access_key", "r2_secret_key",
	"backup_passphrase", "setup_token",
}

// scrubSnapshotDB 清理快照中的凭据。VACUUM 会重写整个文件，
// 确保 SQLite 已释放的页里不会残留旧口令的字节。
func scrubSnapshotDB(path string) error {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer d.Close()
	d.SetMaxOpenConns(1)
	for _, k := range sensitiveSettingKeys {
		if _, err := d.Exec("DELETE FROM settings WHERE key = ?", k); err != nil {
			return err
		}
	}
	if _, err := d.Exec("DELETE FROM settings WHERE key LIKE '%secret%' OR key LIKE '%token%' OR key LIKE '%pass%'"); err != nil {
		return err
	}
	if _, err := d.Exec("VACUUM"); err != nil {
		return err
	}
	return nil
}

// createSecureBackup 返回加密备份文件的临时路径，调用方负责 os.Remove。
func createSecureBackup() (string, error) {
	mu.Lock()
	pass := config.BackupPassphrase
	mu.Unlock()
	if pass == "" {
		return "", errors.New("未配置备份口令，已拒绝生成明文云备份（请先在 系统设置 → 备份口令 中填写）")
	}

	snap, err := snapshotDB()
	if err != nil {
		return "", err
	}
	defer os.Remove(snap)

	if err := scrubSnapshotDB(snap); err != nil {
		return "", fmt.Errorf("清理快照凭据失败: %w", err)
	}
	plain, err := os.ReadFile(snap)
	if err != nil {
		return "", err
	}
	enc, err := encryptBackup(plain, pass)
	if err != nil {
		return "", err
	}

	name := fmt.Sprintf("gorelay_backup_%s%s", time.Now().Format("20060102_150405"), BackupExt)
	out := filepath.Join(os.TempDir(), name)
	if err := os.WriteFile(out, enc, 0600); err != nil {
		return "", err
	}
	return out, nil
}

// backupPassphraseConfigured 供定时任务判断是否需要外发备份。
func backupPassphraseConfigured() bool {
	mu.Lock()
	defer mu.Unlock()
	return config.BackupPassphrase != ""
}

// runDecryptBackup 是 -decrypt-backup 的 CLI 实现。口令优先读环境变量，
// 避免出现在 shell history / ps 里；交互场景下回退到标准输入。
func runDecryptBackup(in, out string) {
	pass := os.Getenv("GORELAY_BACKUP_PASSPHRASE")
	if pass == "" {
		fmt.Print("请输入备份口令: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pass = strings.TrimSpace(line)
	}
	if pass == "" {
		log.Fatal("❌ 未提供备份口令")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		log.Fatalf("❌ 读取备份失败: %v", err)
	}
	plain, err := decryptBackup(data, pass)
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	if out == "" {
		out = strings.TrimSuffix(in, BackupExt)
		if out == in {
			out += ".decrypted.db"
		} else {
			out += ".db"
		}
	}
	if err := os.WriteFile(out, plain, 0600); err != nil {
		log.Fatalf("❌ 写出失败: %v", err)
	}
	fmt.Printf("✅ 备份已解密: %s\n", out)
}
