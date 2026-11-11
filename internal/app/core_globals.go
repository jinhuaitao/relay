// globals.go — 进程级全局变量（数据库句柄、配置、运行时状态表）
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 后续按安全加固需要补充会话/代理/备份相关状态。

package app

import (
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
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

	// oauthStates 保存 GitHub OAuth 的 state -> 过期时间，防止授权码被跨站注入
	oauthStates = make(map[string]time.Time)

	wsUpgrader = websocket.Upgrader{}
	wsClients  = make(map[*wsClient]bool)
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

	// setupToken 是首次初始化的一次性令牌：仅在 IsSetup 为 false 时生成并打印到日志。
	// 远程访问 /setup 必须携带该令牌，防止公网端口扫描器在部署窗口期抢先注册管理员。
	setupToken string

	// trustedProxyNets 由 loadConfig / 设置页写入。atomic.Value 避免读路径与全局 mu 互相死锁。
	trustedProxyNets atomic.Value // []*net.IPNet
)
