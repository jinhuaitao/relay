package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateSecureBackupStripsSecrets 覆盖完整闭环：
// 一致性快照 -> 剥离凭据 -> 加密 -> 解密 -> 校验库结构。
func TestCreateSecureBackupStripsSecrets(t *testing.T) {
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldwd)

	oldDB, oldConf := db, config
	defer func() {
		if db != nil {
			_ = db.Close()
		}
		db, config = oldDB, oldConf
	}()

	initDB()
	if _, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('web_pass', 'SUPER-SECRET-HASH')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_bot_token', 'SUPER-SECRET-TOKEN')"); err != nil {
		t.Fatal(err)
	}

	config.BackupPassphrase = ""
	if _, err := createSecureBackup(); err == nil {
		t.Fatal("未配置备份口令时必须拒绝外发")
	}

	config.BackupPassphrase = "unit-test-passphrase"
	path, err := createSecureBackup()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if !strings.HasSuffix(path, BackupExt) {
		t.Fatalf("备份后缀应为 %s，得到 %s", BackupExt, filepath.Ext(path))
	}

	enc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("SUPER-SECRET")) || bytes.Contains(enc, []byte("SQLite format 3")) {
		t.Fatal("加密文件中出现明文或 SQLite 文件头")
	}
	plain, err := decryptBackup(enc, "unit-test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("SUPER-SECRET")) {
		t.Fatal("脱敏后的数据库中仍残留凭据")
	}
	if !bytes.HasPrefix(plain, []byte("SQLite format 3\x00")) {
		t.Fatal("解密结果不是合法 SQLite 文件")
	}

	restored := filepath.Join(dir, "restored.db")
	if err := os.WriteFile(restored, plain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteDB(restored); err != nil {
		t.Fatalf("恢复后的数据库不可用: %v", err)
	}
}

func TestVerifySQLiteDBRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.db")
	if err := os.WriteFile(bad, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteDB(bad); err == nil {
		t.Fatal("非 SQLite 文件应被拒绝")
	}
}
