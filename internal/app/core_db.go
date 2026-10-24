// db.go — SQLite 建表语句与数据库初始化
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"database/sql"
	"log"

	// 纯 Go 版 SQLite 驱动，注册 "sqlite" 方言（原 main.go 中的空白导入）
	_ "modernc.org/sqlite"
)

const dbSchema = `
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    group_name TEXT, 
    note TEXT,
    entry_agent TEXT,
    entry_port TEXT,
    exit_agent TEXT,
    target_ip TEXT,
    target_port TEXT,
    protocol TEXT,
    bridge_port TEXT,
    traffic_limit INTEGER,
    disabled INTEGER,
    speed_limit INTEGER,
    total_tx INTEGER DEFAULT 0,
    total_rx INTEGER DEFAULT 0,
    lb_strategy TEXT DEFAULT 'random',
    alert_80 INTEGER DEFAULT 0,
    alert_95 INTEGER DEFAULT 0,
    alert_100 INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    ip TEXT,
    category TEXT DEFAULT '',
    action TEXT,
    msg TEXT
);
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,
    tx INTEGER DEFAULT 0,
    rx INTEGER DEFAULT 0
);
`

func initDB() {
	var err error
	db, err = sql.Open("sqlite", DBFile)
	if err != nil {
		log.Fatalf("❌ 无法打开数据库文件: %v", err)
	}

	db.SetMaxOpenConns(1)
	db.Exec("PRAGMA journal_mode=WAL;")
	db.Exec("PRAGMA journal_size_limit = 10485760;")
	db.Exec("PRAGMA wal_autocheckpoint = 100;")
	db.Exec("PRAGMA synchronous = NORMAL;")

	if _, err := db.Exec(dbSchema); err != nil {
		log.Fatalf("❌ 初始化数据库表结构失败: %v", err)
	}

	_, _ = db.Exec("ALTER TABLE rules ADD COLUMN group_name TEXT DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE rules ADD COLUMN lb_strategy TEXT DEFAULT 'random'")
	_, _ = db.Exec("ALTER TABLE rules ADD COLUMN alert_80 INTEGER DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE rules ADD COLUMN alert_95 INTEGER DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE rules ADD COLUMN alert_100 INTEGER DEFAULT 0")
	// 日志分类字段迁移（已存在时忽略错误）
	_, _ = db.Exec("ALTER TABLE logs ADD COLUMN category TEXT DEFAULT ''")
}
