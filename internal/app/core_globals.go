// globals.go — 进程级全局变量（数据库句柄、配置、运行时状态表）
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"database/sql"
	"github.com/gorilla/websocket"
	"sync"
	"time"
)

var (
	db               *sql.DB
	config           AppConfig
	agents           = make(map[string]*AgentInfo)
	rules            = make([]LogicalRule, 0)
	mu               sync.Mutex
	runningListeners sync.Map
	activeTasks      sync.Map
	activeTargets    sync.Map
	agentTraffic     sync.Map
	agentUserCounts  sync.Map
	targetHealthMap  sync.Map
	sessions         = make(map[string]time.Time)
	configDirty      int32

	rrCounters   sync.Map
	connCounters sync.Map

	loginAttempts = sync.Map{}
	blockUntil    = sync.Map{}

	wsUpgrader = websocket.Upgrader{}
	wsClients  = make(map[*websocket.Conn]bool)
	wsMu       sync.Mutex

	isMasterTLS bool = false
	useTLS      bool = false

	cpuMu        sync.Mutex
	lastCPUIdle  uint64
	lastCPUTotal uint64

	// 每日流量统计缓冲（提升数据库性能）
	dailyTxBuf int64
	dailyRxBuf int64

	// TG 周备份的幂等键（持久化于 settings 表，键名 last_backup_date）
	lastTgBackupDate string
)
