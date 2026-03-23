package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"image/png"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/acme/autocert"
	_ "modernc.org/sqlite"
)

// --- 配置与常量 ---

const (
	AppVersion      = "v3.0.98"
	DBFile          = "data.db"
	WebPort         = ":8888"
	DownloadURL     = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
	GithubLatestAPI = "https://api.github.com/repos/jinhuaitao/relay/releases/latest"
	TCPKeepAlive    = 60 * time.Second
	UDPBufferSize   = 4 * 1024 * 1024
	CopyBufferSize  = 32 * 1024
	MaxLogEntries   = 200
	MaxLogRetention = 1000
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, CopyBufferSize)
		return &b
	},
}

// --- 数据结构 ---

type LogicalRule struct {
	ID           string `json:"id"`
	Group        string `json:"group"`
	Note         string `json:"note"`
	EntryAgent   string `json:"entry_agent"`
	EntryPort    string `json:"entry_port"`
	ExitAgent    string `json:"exit_agent"`
	TargetIP     string `json:"target_ip"`
	TargetPort   string `json:"target_port"`
	Protocol     string `json:"protocol"`
	BridgePort   string `json:"bridge_port"`
	TrafficLimit int64  `json:"traffic_limit"`
	Disabled     bool   `json:"disabled"`
	SpeedLimit   int64  `json:"speed_limit"`
	LBStrategy   string `json:"lb_strategy"`

	TotalTx   int64 `json:"total_tx"`
	TotalRx   int64 `json:"total_rx"`
	UserCount int64 `json:"user_count"`

	TargetStatus  bool  `json:"-"`
	TargetLatency int64 `json:"-"`

	Alert80  bool `json:"alert_80"`
	Alert95  bool `json:"alert_95"`
	Alert100 bool `json:"alert_100"`
}

type OpLog struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Msg    string `json:"msg"`
}

type DailyStat struct {
	Date string `json:"Date"`
	Tx   int64  `json:"Tx"`
	Rx   int64  `json:"Rx"`
}

type AppConfig struct {
	WebUser            string            `json:"web_user"`
	WebPass            string            `json:"web_pass"`
	AgentToken         string            `json:"agent_token"`
	AgentTokens        map[string]string `json:"agent_tokens"`
	AgentPorts         string            `json:"agent_ports"`
	MasterDomain       string            `json:"master_domain"`
	PanelDomain        string            `json:"panel_domain"`
	IsSetup            bool              `json:"is_setup"`
	TgBotToken         string            `json:"tg_bot_token"`
	TgChatID           string            `json:"tg_chat_id"`
	TwoFAEnabled       bool              `json:"two_fa_enabled"`
	TwoFASecret        string            `json:"two_fa_secret"`
	GithubClientID     string            `json:"github_client_id"`
	GithubClientSecret string            `json:"github_client_secret"`
	GithubAllowedUsers string            `json:"github_allowed_users"`
	TrafficResetDay    int               `json:"traffic_reset_day"`
	LastResetMonth     string            `json:"last_reset_month"`
	Rules              []LogicalRule     `json:"saved_rules"`
	Logs               []OpLog           `json:"logs"`
}

type ForwardTask struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	Target     string `json:"target"`
	SpeedLimit int64  `json:"speed_limit"`
	LBStrategy string `json:"lb_strategy"`
}

type TrafficReport struct {
	TaskID    string `json:"task_id"`
	TxDelta   int64  `json:"tx"`
	RxDelta   int64  `json:"rx"`
	UserCount int64  `json:"uc"`
}

type HealthReport struct {
	TaskID  string `json:"task_id"`
	Latency int64  `json:"lat"`
}

type AgentInfo struct {
	Name      string   `json:"name"`
	RemoteIP  string   `json:"remote_ip"`
	Conn      net.Conn `json:"-"`
	SysStatus string   `json:"sys_status"`
	ConnectedAt time.Time `json:"-"`
}

type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type TrafficCounter struct {
	Rx int64
	Tx int64
}

type udpSession struct {
	conn       *net.UDPConn
	lastActive time.Time
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type WSDashboardData struct {
	TotalTraffic int64             `json:"total_traffic"`
	SpeedTx      int64             `json:"speed_tx"`
	SpeedRx      int64             `json:"speed_rx"`
	Agents       []AgentStatusData `json:"agents"`
	Rules        []RuleStatusData  `json:"rules"`
	Logs         []OpLog           `json:"logs"`
}

type AgentStatusData struct {
	Name      string `json:"name"`
	SysStatus string `json:"sys_status"`
}

type RuleStatusData struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
    Group     string `json:"group"`
	Total     int64  `json:"total"`
	Tx        int64  `json:"tx"`
	Rx        int64  `json:"rx"`
	UserCount int64  `json:"uc"`
	Limit     int64  `json:"limit"`
	Status    bool   `json:"status"`
	Latency   int64  `json:"latency"`
}

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
)

// --- 数据库初始化与优化 ---

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
}

// --- 基础工具函数 ---

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generateSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt + password))
	return hex.EncodeToString(h.Sum(nil))
}

func md5Hash(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func checkLoginRateLimit(ip string) bool {
	if t, ok := blockUntil.Load(ip); ok {
		if time.Now().Before(t.(time.Time)) {
			return false
		}
		blockUntil.Delete(ip)
		loginAttempts.Delete(ip)
	}
	return true
}

func recordLoginFail(ip string) {
	v, _ := loginAttempts.LoadOrStore(ip, 0)
	count := v.(int) + 1
	loginAttempts.Store(ip, count)
	if count >= 5 {
		blockUntil.Store(ip, time.Now().Add(15*time.Minute))
	}
}

func performSelfUpdate() error {
	arch := runtime.GOARCH
	osName := runtime.GOOS
	suffix := ""
	if osName == "linux" {
		suffix = "-linux-" + arch
	} else if osName == "darwin" {
		suffix = "-darwin-" + arch
	} else if osName == "windows" {
		suffix = "-windows-" + arch + ".exe"
	} else {
		return fmt.Errorf("不支持的操作系统")
	}

	targetURL := DownloadURL + suffix
	log.Printf("正在下载更新: %s", targetURL)

	resp, err := http.Get(targetURL)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取运行路径: %v", err)
	}

	tmpPath := exePath + ".new"
	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}
	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	os.Chmod(tmpPath, 0755)

	oldPath := exePath + ".old"
	os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Rename(oldPath, exePath)
		return fmt.Errorf("覆盖文件失败: %v", err)
	}
	return nil
}

// --- 主程序 ---

func main() {
	setRLimit()
	mode := flag.String("mode", "master", "运行模式")
	name := flag.String("name", "", "Agent名称")
	connect := flag.String("connect", "", "Master地址")
	token := flag.String("token", "", "通信Token")
	serviceOp := flag.String("service", "", "install | uninstall")
	tlsFlag := flag.Bool("tls", false, "使用 TLS 加密连接")
	flag.Parse()

	if *serviceOp != "" {
		handleService(*serviceOp, *mode, *name, *connect, *token, *tlsFlag)
		return
	}

	setupSignalHandler()

	if *mode == "master" {
		initDB()
		loadConfig()
		runMaster()
	} else if *mode == "agent" {
		if *name == "" || *connect == "" || *token == "" {
			log.Fatal("Agent模式参数不足")
		}
		useTLS = *tlsFlag
		runAgent(*name, *connect, *token)
	} else {
		log.Fatal("未知模式")
	}
}

func setRLimit() {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		var rLimit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
			rLimit.Cur = 1000000
			rLimit.Max = 1000000
			syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		}
	}
}

func getSysStatus() string {
	var cpuPct, memPct, diskPct float64

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/stat"); err == nil {
			lines := strings.Split(string(data), "\n")
			if len(lines) > 0 {
				fields := strings.Fields(lines[0])
				if len(fields) > 4 && fields[0] == "cpu" {
					var ticks [8]uint64
					for i := 1; i < len(fields) && i <= 8; i++ {
						ticks[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
					}
					idleTicks := ticks[3] + ticks[4] 
					var totalTicks uint64
					for _, t := range ticks {
						totalTicks += t
					}

					cpuMu.Lock()
					diffIdle := float64(idleTicks - lastCPUIdle)
					diffTotal := float64(totalTicks - lastCPUTotal)
					if diffTotal > 0 {
						cpuPct = ((diffTotal - diffIdle) / diffTotal) * 100.0
					}
					lastCPUIdle = idleTicks
					lastCPUTotal = totalTicks
					cpuMu.Unlock()
				}
			}
		}

		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			var total, available, free, buffers, cached uint64
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					val, _ := strconv.ParseUint(fields[1], 10, 64)
					if fields[0] == "MemTotal:" { total = val }
					if fields[0] == "MemAvailable:" { available = val }
					if fields[0] == "MemFree:" { free = val }
					if fields[0] == "Buffers:" { buffers = val }
					if fields[0] == "Cached:" { cached = val }
				}
			}
			if total > 0 {
				if available == 0 {
					available = free + buffers + cached
				}
				if available < total {
					memPct = (float64(total-available) / float64(total)) * 100.0
				}
			}
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs("/", &stat); err == nil {
			used := stat.Blocks - stat.Bfree
			nonRootTotal := used + stat.Bavail 
			if nonRootTotal > 0 {
				diskPct = (float64(used) / float64(nonRootTotal)) * 100.0
			}
		}
	} else {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memPct = 1.0 
		cpuPct = float64(runtime.NumGoroutine()) 
	}

	if cpuPct < 0 { cpuPct = 0 } else if cpuPct > 100 { cpuPct = 100 }
	if memPct < 0 { memPct = 0 } else if memPct > 100 { memPct = 100 }
	if diskPct < 0 { diskPct = 0 } else if diskPct > 100 { diskPct = 100 }

	return fmt.Sprintf("CPU:%.1f|MEM:%.1f|DSK:%.1f", cpuPct, memPct, diskPct)
}

func getClientIP(r *http.Request) string {
	if r == nil {
		return "System"
	}
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func addLog(r *http.Request, action, msg string) {
	ip := getClientIP(r)
	now := time.Now().Format("01-02 15:04:05")
	if db != nil {
		_, _ = db.Exec("INSERT INTO logs (time, ip, action, msg) VALUES (?,?,?,?)", now, ip, action, msg)
	}
}

func addSystemLog(ip, action, msg string) {
	now := time.Now().Format("01-02 15:04:05")
	if db != nil {
		_, _ = db.Exec("INSERT INTO logs (time, ip, action, msg) VALUES (?,?,?,?)", now, ip, action, msg)
	}
}

func handleService(op, mode, name, connect, token string, useTLS bool) {
	if os.Geteuid() != 0 {
		log.Fatal("需 root 权限")
	}
	exe, _ := os.Executable()
	exe, _ = filepath.Abs(exe)
	tlsParam := ""
	if useTLS {
		tlsParam = " -tls"
	}

	svcName := "relay"
	if mode == "agent" {
		svcName = "gorelay"
	}

	args := fmt.Sprintf("-mode %s -name \"%s\" -connect \"%s\" -token \"%s\"%s", mode, name, connect, token, tlsParam)
	isSys := false
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		isSys = true
	}
	isAlpine := false
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		isAlpine = true
	}

	if op == "install" {
		if isSys {
			c := fmt.Sprintf("[Unit]\nDescription=GoRelay Service (%s)\nAfter=network.target\n[Service]\nType=simple\nExecStart=%s %s\nRestart=always\nUser=root\nLimitNOFILE=1000000\n[Install]\nWantedBy=multi-user.target", svcName, exe, args)
			os.WriteFile(fmt.Sprintf("/etc/systemd/system/%s.service", svcName), []byte(c), 0644)
			exec.Command("systemctl", "enable", svcName).Run()
			exec.Command("systemctl", "restart", svcName).Run()
			log.Printf("Systemd 服务 %s 已安装", svcName)
		} else if isAlpine {
			c := fmt.Sprintf("#!/sbin/openrc-run\nname=\"%s\"\ncommand=\"%s\"\ncommand_args=\"%s\"\ncommand_background=true\npidfile=\"/run/%s.pid\"\nrc_ulimit=\"-n 1000000\"\ndepend(){ need net; }", svcName, exe, args, svcName)
			os.WriteFile(fmt.Sprintf("/etc/init.d/%s", svcName), []byte(c), 0755)
			exec.Command("rc-update", "add", svcName, "default").Run()
			exec.Command("rc-service", svcName, "restart").Run()
			log.Printf("OpenRC 服务 %s 已安装", svcName)
		} else {
			exec.Command("nohup", exe, args, "&").Start()
			log.Println("已通过 nohup 启动")
		}
	} else {
		if isSys {
			exec.Command("systemctl", "disable", svcName).Run()
			exec.Command("systemctl", "stop", svcName).Run()
			os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", svcName))
			exec.Command("systemctl", "daemon-reload").Run()
		}
		if isAlpine {
			exec.Command("rc-update", "del", svcName, "default").Run()
			exec.Command("rc-service", svcName, "stop").Run()
			os.Remove(fmt.Sprintf("/etc/init.d/%s", svcName))
		}
		log.Printf("服务 %s 已卸载", svcName)
	}
}

func doSelfUninstall() {
	log.Println("执行自毁程序...")
	services := []string{"relay", "gorelay"}

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/systemd/system/%s.service", s)); err == nil {
				exec.Command("systemctl", "disable", s).Run()
				exec.Command("systemctl", "stop", s).Run()
				os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", s))
			}
		}
		exec.Command("systemctl", "daemon-reload").Run()
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/init.d/%s", s)); err == nil {
				exec.Command("rc-update", "del", s, "default").Run()
				exec.Command("rc-service", s, "stop").Run()
				os.Remove(fmt.Sprintf("/etc/init.d/%s", s))
			}
		}
	}

	exe, err := os.Executable()
	if err == nil {
		realPath, err := filepath.EvalSymlinks(exe)
		if err != nil {
			realPath = exe
		}
		absPath, _ := filepath.Abs(realPath)
		os.Remove(absPath)
	}
	os.Exit(0)
}

// ================= TG BOT INTERACTIVE =================

func tgRequest(method string, payload interface{}) {
	mu.Lock()
	token := config.TgBotToken
	mu.Unlock()
	if token == "" {
		return
	}

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)
	b, _ := json.Marshal(payload)
	go func() {
		req, _ := http.NewRequest("POST", urlStr, bytes.NewBuffer(b))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req)
	}()
}

func sendTelegram(text string) {
	mu.Lock()
	chatID := config.TgChatID
	mu.Unlock()
	if chatID == "" {
		return
	}
	tgRequest("sendMessage", map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	})
}

// --- TG 交互增强工具 ---

// 终极美学进度条：支持传入自定义的 UI 设计字符
func makeAestheticBar(percent float64, fillChar, emptyChar string) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	
	totalWidth := 12 // 12格是极简符号的视觉黄金比例
	
	filledBlocks := int((percent / 100.0) * float64(totalWidth))
	
	// 保证只要有占用，就至少亮起一格，避免 1% 显示为空
	if percent > 0 && filledBlocks == 0 {
		filledBlocks = 1 
	}
	if filledBlocks > totalWidth {
		filledBlocks = totalWidth
	}
	
	emptyBlocks := totalWidth - filledBlocks
	
	return strings.Repeat(fillChar, filledBlocks) + strings.Repeat(emptyChar, emptyBlocks)
}


// 向 Telegram 自动注册原生快捷菜单 (Menu Button)
func setupTgBotCommands() {
	mu.Lock()
	token := config.TgBotToken
	mu.Unlock()
	if token == "" {
		return
	}

	commands := []map[string]string{
		{"command": "menu", "description": "🎛️ 打开智能中控台主菜单"},
		{"command": "status", "description": "📊 查看节点与实时流量状态"},
		{"command": "rules", "description": "📜 管理转发规则 (启停)"},
	}

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", token)
	b, _ := json.Marshal(map[string]interface{}{"commands": commands})

	go func() {
		req, _ := http.NewRequest("POST", urlStr, bytes.NewBuffer(b))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req)
	}()
}

// --- TG 云备份功能核心 ---
func sendTelegramDocument(filePath string, caption string) {
	mu.Lock()
	token := config.TgBotToken
	chatID := config.TgChatID
	mu.Unlock()
	if token == "" || chatID == "" {
		return
	}

	if db != nil {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", caption)
	_ = writer.WriteField("parse_mode", "HTML")

	fileName := fmt.Sprintf("gorelay_backup_%s.db", time.Now().Format("20060102_150405"))
	part, err := writer.CreateFormFile("document", fileName)
	if err == nil {
		io.Copy(part, file)
	}
	writer.Close()

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)
	req, _ := http.NewRequest("POST", urlStr, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	client.Do(req)
}

func autoBackupLoop() {
	var lastBackupWeek int = -1
	for {
		time.Sleep(1 * time.Hour)
		now := time.Now()

		mu.Lock()
		token := config.TgBotToken
		chatID := config.TgChatID
		mu.Unlock()

		if token == "" || chatID == "" {
			continue
		}

		_, week := now.ISOWeek()

		if now.Weekday() == time.Monday && now.Hour() == 2 && lastBackupWeek != week {
			lastBackupWeek = week
			sendTelegramDocument(DBFile, fmt.Sprintf("☁️ <b>自动云备份</b>\n\n这是本周的系统数据备份。\n时间: %s", now.Format("2006-01-02 15:04:05")))
		}
	}
}

type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

func sendTgMenu(chatID string) {
	markup := map[string]interface{}{
		"inline_keyboard": [][]InlineButton{
			{{Text: "📊 节点与流量状态", CallbackData: "cmd:status"}},
			{{Text: "📜 规则管理 (启停)", CallbackData: "cmd:rules"}},
			{{Text: "💾 立即云端备份", CallbackData: "cmd:backup"}},
			{{Text: "🔄 远程重启面板", CallbackData: "cmd:restart"}},
		},
	}
	tgRequest("sendMessage", map[string]interface{}{
		"chat_id":      chatID,
		"text":         "🤖 <b>GoRelay Pro 智能中控台</b>\n\n请点击下方按钮执行快捷操作：",
		"parse_mode":   "HTML",
		"reply_markup": markup,
	})
}

func buildRulesMenuMarkup(page int) map[string]interface{} {
	var rows [][]InlineButton
	mu.Lock()
	defer mu.Unlock()

	pageSize := 10 // 每页显示的规则数量
	totalRules := len(rules)
	totalPages := (totalRules + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > totalRules {
		end = totalRules
	}

	// 渲染当前页的规则按钮
	for i := start; i < end; i++ {
		r := rules[i]
		status := "🟢"
		if r.Disabled {
			status = "🔴"
		}
		text := fmt.Sprintf("%s %s", status, r.Note)
		if r.Group != "" {
			text += fmt.Sprintf(" (%s)", r.Group)
		}
		// 回调数据中带上当前页码，以便操作后能停留在本页
		rows = append(rows, []InlineButton{{Text: text, CallbackData: fmt.Sprintf("toggle:%s:%d", r.ID, page)}})
	}

	// 渲染分页导航行
	var navRow []InlineButton
	if page > 1 {
		navRow = append(navRow, InlineButton{Text: "⬅️ 上一页", CallbackData: fmt.Sprintf("page:%d", page-1)})
	}
	navRow = append(navRow, InlineButton{Text: fmt.Sprintf("📄 %d / %d", page, totalPages), CallbackData: "noop"})
	if page < totalPages {
		navRow = append(navRow, InlineButton{Text: "下一页 ➡️", CallbackData: fmt.Sprintf("page:%d", page+1)})
	}
	rows = append(rows, navRow)

	// 底部返回按钮
	rows = append(rows, []InlineButton{{Text: "🔙 返回主菜单", CallbackData: "cmd:menu"}})
	return map[string]interface{}{"inline_keyboard": rows}
}

func startTgBotLoop() {
	var offset int64 = 0
	for {
		mu.Lock()
		token := config.TgBotToken
		allowedChat := config.TgChatID
		mu.Unlock()

		if token == "" || allowedChat == "" {
			time.Sleep(10 * time.Second)
			continue
		}

		client := http.Client{Timeout: 65 * time.Second}
		urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=60", token, offset)
		resp, err := client.Get(urlStr)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		var res struct {
			Result []struct {
				UpdateID int64 `json:"update_id"`
				Message  *struct {
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
				CallbackQuery *struct {
					ID      string `json:"id"`
					Data    string `json:"data"`
					Message *struct {
						MessageID int64 `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
					} `json:"message"`
				} `json:"callback_query"`
			} `json:"result"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			resp.Body.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		resp.Body.Close()

		for _, update := range res.Result {
			offset = update.UpdateID + 1

			// 处理直接输入的指令
			if update.Message != nil {
				chatIdStr := fmt.Sprintf("%d", update.Message.Chat.ID)
				if chatIdStr != allowedChat {
					continue
				}
				text := strings.TrimSpace(update.Message.Text)
				if text == "/start" || text == "/menu" || text == "/help" {
					sendTgMenu(chatIdStr)
				} else if text == "/status" {
					// 模拟触发状态按钮
					update.CallbackQuery = &struct {
						ID      string `json:"id"`
						Data    string `json:"data"`
						Message *struct {
							MessageID int64 `json:"message_id"`
							Chat      struct {
								ID int64 `json:"id"`
							} `json:"chat"`
						} `json:"message"`
					}{ID: "", Data: "cmd:status", Message: &struct {
						MessageID int64 `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
					}{MessageID: 0, Chat: struct {
						ID int64 `json:"id"`
					}{ID: update.Message.Chat.ID}}}
				} else if text == "/rules" {
					// 模拟触发规则按钮
					update.CallbackQuery = &struct {
						ID      string `json:"id"`
						Data    string `json:"data"`
						Message *struct {
							MessageID int64 `json:"message_id"`
							Chat      struct {
								ID int64 `json:"id"`
							} `json:"chat"`
						} `json:"message"`
					}{ID: "", Data: "cmd:rules", Message: &struct {
						MessageID int64 `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
					}{MessageID: 0, Chat: struct {
						ID int64 `json:"id"`
					}{ID: update.Message.Chat.ID}}}
				}
			}

			// 处理内联键盘回调
			if update.CallbackQuery != nil {
				chatIdStr := fmt.Sprintf("%d", update.CallbackQuery.Message.Chat.ID)
				if chatIdStr != allowedChat {
					continue
				}

				if update.CallbackQuery.ID != "" {
					tgRequest("answerCallbackQuery", map[string]interface{}{"callback_query_id": update.CallbackQuery.ID})
				}

				data := update.CallbackQuery.Data
				msgID := update.CallbackQuery.Message.MessageID

				if data == "noop" {
					continue
				} else if data == "cmd:menu" {
					markup := map[string]interface{}{
						"inline_keyboard": [][]InlineButton{
							{{Text: "📊 节点与流量状态", CallbackData: "cmd:status"}},
							{{Text: "📜 规则管理 (启停)", CallbackData: "cmd:rules"}},
							{{Text: "💾 立即云端备份", CallbackData: "cmd:backup"}},
							{{Text: "🔄 远程重启面板", CallbackData: "cmd:restart"}},
						},
					}
					tgAction := "editMessageText"
					if msgID == 0 { tgAction = "sendMessage" }
					tgRequest(tgAction, map[string]interface{}{
						"chat_id":      chatIdStr,
						"message_id":   msgID,
						"text":         "🤖 <b>GoRelay Pro 智能中控台</b>\n\n请点击下方按钮执行快捷操作：",
						"parse_mode":   "HTML",
						"reply_markup": markup,
					})
				} else if data == "cmd:status" {
					mu.Lock()
					var tx, rx int64
					for _, r := range rules {
						tx += r.TotalTx
						rx += r.TotalRx
					}
					reply := fmt.Sprintf("📊 <b>系统实时状态</b>\n\n🌐 总中继流量: <b>%s</b>\n🔌 在线节点数: <b>%d</b>\n📜 转发规则数: <b>%d</b>\n\n--- 探针状态 ---\n", formatBytes(tx+rx), len(agents), len(rules))
					
					// === 新增 TG 节点排序逻辑 ===
					var sortedAgents []*AgentInfo
					for _, a := range agents {
						sortedAgents = append(sortedAgents, a)
					}
					sort.Slice(sortedAgents, func(i, j int) bool {
						return sortedAgents[i].ConnectedAt.Before(sortedAgents[j].ConnectedAt)
					})

					// 将原来的 for _, a := range agents 改为遍历 sortedAgents
					for _, a := range sortedAgents {
					// ===========================
					
						var cpu, mem, dsk float64
						parts := strings.Split(a.SysStatus, "|")
						for _, p := range parts {
							kv := strings.Split(p, ":")
							if len(kv) == 2 {
								v, _ := strconv.ParseFloat(kv[1], 64)
								if kv[0] == "CPU" { cpu = v }
								if kv[0] == "MEM" { mem = v }
								if kv[0] == "DSK" { dsk = v }
							}
						}
						reply += fmt.Sprintf("💻 <b>%s</b> <code>[%s]</code>\n", a.Name, a.RemoteIP)
						reply += fmt.Sprintf(" ├ 🟢 <code>CPU: %5.1f%% [%s]</code>\n", cpu, makeAestheticBar(cpu, "━", "─"))
						reply += fmt.Sprintf(" ├ 🔵 <code>MEM: %5.1f%% [%s]</code>\n", mem, makeAestheticBar(mem, "━", "─"))
						reply += fmt.Sprintf(" └ 🟡 <code>DSK: %5.1f%% [%s]</code>\n\n", dsk, makeAestheticBar(dsk, "━", "─"))

					}
					if len(agents) == 0 {
						reply += "⚠️ <i>暂无节点在线</i>\n\n"
					}
					mu.Unlock()

					// 查询近 30 天流量消耗趋势
					reply += "--- 历史流量趋势 ---\n"
					
					var total30Tx, total30Rx int64
					var historyLines []string
					if db != nil {
						dsRows, err := db.Query("SELECT date, tx, rx FROM daily_stats ORDER BY date DESC LIMIT 30")
						if err == nil {
							defer dsRows.Close()
							
							for dsRows.Next() {
								var d string
								var dTx, dRx int64
								dsRows.Scan(&d, &dTx, &dRx)
								total30Tx += dTx
								total30Rx += dRx
								
								if len(historyLines) < 10 {
									shortDate := d
									if len(d) == 10 { shortDate = d[5:] }
									historyLines = append(historyLines, fmt.Sprintf("📅 %s ⬆️%s ⬇️%s", shortDate, formatBytes(dTx), formatBytes(dRx)))
								}
							}
						}
					}
					
					if len(historyLines) > 0 {
						reply += fmt.Sprintf("🗓️ <b>近 30 天总计: %s</b>\n", formatBytes(total30Tx+total30Rx))
						for _, line := range historyLines { reply += line + "\n" }
					} else {
						reply += "<i>暂无历史流量数据</i>\n"
					}
					
					nowTime := time.Now().Format("2006-01-02 15:04:05")
					reply += fmt.Sprintf("\n<blockquote expandable>🕒 探针最后同步时间: \n<code>%s</code></blockquote>", nowTime)

					markup := map[string]interface{}{
						"inline_keyboard": [][]InlineButton{{{Text: "🔙 返回主菜单", CallbackData: "cmd:menu"}, {Text: "🔄 刷新状态", CallbackData: "cmd:status"}}},
					}
					tgAction := "editMessageText"
					if msgID == 0 { tgAction = "sendMessage" }
					tgRequest(tgAction, map[string]interface{}{
						"chat_id":      chatIdStr,
						"message_id":   msgID,
						"text":         reply,
						"parse_mode":   "HTML",
						"reply_markup": markup,
					})
				} else if data == "cmd:rules" || strings.HasPrefix(data, "page:") {
					page := 1
					if strings.HasPrefix(data, "page:") {
						pStr := strings.TrimPrefix(data, "page:")
						if p, err := strconv.Atoi(pStr); err == nil {
							page = p
						}
					}
					tgAction := "editMessageText"
					if msgID == 0 { tgAction = "sendMessage" }
					tgRequest(tgAction, map[string]interface{}{
						"chat_id":      chatIdStr,
						"message_id":   msgID,
						"text":         "📜 <b>转发规则管理</b>\n\n点击下方按钮可一键切换 启动/暂停 状态：",
						"parse_mode":   "HTML",
						"reply_markup": buildRulesMenuMarkup(page),
					})
				} else if data == "cmd:backup" {
					go sendTelegramDocument(DBFile, fmt.Sprintf("☁️ <b>手动云备份</b>\n\n数据库文件已成功导出。\n时间: %s", time.Now().Format("2006-01-02 15:04:05")))
				} else if strings.HasPrefix(data, "toggle:") {
					// 格式: toggle:id:page
					parts := strings.Split(data, ":")
					if len(parts) >= 2 {
						id := parts[1]
						page := 1
						if len(parts) >= 3 {
							p, _ := strconv.Atoi(parts[2])
							page = p
						}
						
						mu.Lock()
						for i := range rules {
							if rules[i].ID == id {
								rules[i].Disabled = !rules[i].Disabled
								break
							}
						}
						saveConfigNoLock()
						mu.Unlock()
						go pushConfigToAll()

						tgRequest("editMessageText", map[string]interface{}{
							"chat_id":      chatIdStr,
							"message_id":   msgID,
							"text":         "📜 <b>转发规则管理</b>\n\n状态已更新！点击下方按钮可继续切换：",
							"parse_mode":   "HTML",
							"reply_markup": buildRulesMenuMarkup(page),
						})
					}
				} else if data == "cmd:restart" {
					// 增加二级确认防护
					markup := map[string]interface{}{
						"inline_keyboard": [][]InlineButton{
							{{Text: "⚠️ 确认重启", CallbackData: "action:confirm_restart"}},
							{{Text: "❌ 取消操作", CallbackData: "cmd:menu"}},
						},
					}
					tgRequest("editMessageText", map[string]interface{}{
						"chat_id":      chatIdStr,
						"message_id":   msgID,
						"text":         "⚠️ <b>危险操作确认</b>\n\n您正在尝试远程重启整个中控系统，这会导致所有网络连接短暂中断。确定要继续吗？",
						"parse_mode":   "HTML",
						"reply_markup": markup,
					})
				} else if data == "action:confirm_restart" {
					tgRequest("editMessageText", map[string]interface{}{
						"chat_id":    chatIdStr,
						"message_id": msgID,
						"text":       "🔄 接收到安全指令，系统正在执行重启...",
					})
					go func() {
						time.Sleep(2 * time.Second)
						doRestart()
					}()
				}
			}
		}
	}
}

// ================= TRAFFIC AUTO RESET =================

func trafficResetLoop() {
	for {
		time.Sleep(1 * time.Hour)
		
		mu.Lock()
		day := config.TrafficResetDay
		lastM := config.LastResetMonth
		mu.Unlock()

		if day <= 0 || day > 31 {
			continue
		}

		now := time.Now()
		currentM := now.Format("2006-01")
		
		if now.Day() >= day && lastM != currentM {
			mu.Lock()
			for i := range rules {
				rules[i].TotalTx = 0
				rules[i].TotalRx = 0
				rules[i].Alert80 = false
				rules[i].Alert95 = false
				rules[i].Alert100 = false
			}
			config.LastResetMonth = currentM
			saveConfigNoLock()
			mu.Unlock()
			
			sendTelegram(fmt.Sprintf("📅 <b>账单日触发</b>\n系统已自动清零本月所有规则的流量统计！"))
			go pushConfigToAll()
		}
	}
}


// ================= MASTER =================

// ================= TG DAILY REPORT =================

func dailyTrafficReportLoop() {
	var lastReportDate string
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()

		if now.Hour() == 23 && now.Minute() >= 59 {
			today := now.Format("2006-01-02")
			if lastReportDate == today {
				continue
			}

			flushDailyStats()

			if db == nil {
				continue
			}

			var tx, rx int64
			err := db.QueryRow("SELECT tx, rx FROM daily_stats WHERE date = ?", today).Scan(&tx, &rx)
			if err == nil && (tx > 0 || rx > 0) {
				msg := fmt.Sprintf("📈 <b>每日流量日报</b>\n\n🗓️ 日期: %s\n⬆️ 今日上传: %s\n⬇️ 今日下载: %s\n🌐 今日总消耗: <b>%s</b>",
					today, formatBytes(tx), formatBytes(rx), formatBytes(tx+rx))
				sendTelegram(msg)
			}
			lastReportDate = today
		}
	}
}

// ================= MASTER =================

func runMaster() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			if atomic.CompareAndSwapInt32(&configDirty, 1, 0) {
				saveConfig()
			}
			cleanOldLogs()
			flushDailyStats()
			if db != nil {
				db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
			}
		}
	}()
	go broadcastLoop()
	go startTgBotLoop()   
	go autoBackupLoop()   
	go trafficResetLoop()
	go dailyTrafficReportLoop()

	mu.Lock()
	panelDomain := config.PanelDomain
	nodeDomain := config.MasterDomain
	portsStr := config.AgentPorts
	if portsStr == "" {
		portsStr = "9999"
	}
	mu.Unlock()

	var tlsConfig *tls.Config
	isMasterTLS = false

	var allowedDomains []string
	if panelDomain != "" && !strings.Contains(panelDomain, "127.0.0.1") && !strings.Contains(panelDomain, "localhost") {
		allowedDomains = append(allowedDomains, panelDomain)
	}
	if nodeDomain != "" && !strings.Contains(nodeDomain, "127.0.0.1") && !strings.Contains(nodeDomain, "localhost") {
		if nodeDomain != panelDomain {
			allowedDomains = append(allowedDomains, nodeDomain)
		}
	}

	if len(allowedDomains) > 0 {
		log.Printf("🌐 检测到有效域名: %v，准备全自动申请合法 TLS 证书", allowedDomains)
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(allowedDomains...),
			Cache:      autocert.DirCache("certs"),
		}
		tlsConfig = certManager.TLSConfig()
		isMasterTLS = true

		go func() {
			err := http.ListenAndServe(":80", certManager.HTTPHandler(nil))
			if err != nil {
				log.Printf("⚠️ 80 端口启动失败 (请确保未被占用且开放了防火墙): %v", err)
			}
		}()
	} else {
		log.Println("⚠️ 未配置有效公网域名，Agent 和面板将以纯 TCP / HTTP 明文模式运行")
	}

	ports := strings.Split(portsStr, ",")
	for _, pStr := range ports {
		pStr = strings.TrimSpace(pStr)
		if pStr == "" {
			continue
		}
		if !strings.Contains(pStr, ":") {
			pStr = ":" + pStr
		}

		go func(p string) {
			var ln net.Listener
			var err error

			if isMasterTLS && tlsConfig != nil {
				ln, err = tls.Listen("tcp", p, tlsConfig)
			} else {
				ln, err = net.Listen("tcp", p)
			}

			if err != nil {
				log.Printf("❌ 监听端口 %s 失败: %v", p, err)
				return
			}
			
			if isMasterTLS {
				log.Printf("✅ Agent 监听端口启动 (安全 TLS 模式): %s", p)
			} else {
				log.Printf("✅ Agent 监听端口启动 (纯 TCP 模式): %s", p)
			}

			for {
				c, err := ln.Accept()
				if err == nil {
					go handleAgentConn(c)
				}
			}
		}(pStr)
	}

	http.HandleFunc("/", authMiddleware(handleDashboard))
	http.HandleFunc("/ws", authMiddleware(handleWS))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/setup", handleSetup)
	http.HandleFunc("/add", authMiddleware(handleAddRule))
	http.HandleFunc("/edit", authMiddleware(handleEditRule))
	http.HandleFunc("/delete", authMiddleware(handleDeleteRule))
	http.HandleFunc("/toggle", authMiddleware(handleToggleRule))
	http.HandleFunc("/reset_traffic", authMiddleware(handleResetTraffic))
	http.HandleFunc("/batch", authMiddleware(handleBatchRule))
	http.HandleFunc("/delete_agent", authMiddleware(handleDeleteAgent))
	http.HandleFunc("/update_settings", authMiddleware(handleUpdateSettings))
	http.HandleFunc("/download_config", authMiddleware(handleDownloadConfig))
	http.HandleFunc("/upload_config", authMiddleware(handleUploadConfig))
	http.HandleFunc("/export_logs", authMiddleware(handleExportLogs))
	http.HandleFunc("/clear_logs", authMiddleware(handleClearLogs))
	http.HandleFunc("/export_rules", authMiddleware(handleExportRules))
	http.HandleFunc("/import_rules", authMiddleware(handleImportRules))
	http.HandleFunc("/2fa/generate", authMiddleware(handle2FAGenerate))
	http.HandleFunc("/2fa/verify", authMiddleware(handle2FAVerify))
	http.HandleFunc("/2fa/disable", authMiddleware(handle2FADisable))
	http.HandleFunc("/restart", authMiddleware(handleRestart))
	http.HandleFunc("/update_sys", authMiddleware(handleUpdateSystem))
	http.HandleFunc("/update_agent", authMiddleware(handleUpdateAgent))
	http.HandleFunc("/check_update", authMiddleware(handleCheckUpdate))
	http.HandleFunc("/gen_agent_token", authMiddleware(handleGenAgentToken))
	
	http.HandleFunc("/oauth/github/login", handleGithubLogin)
	http.HandleFunc("/oauth/github/callback", handleGithubCallback)
	
	http.HandleFunc("/manifest.json", handleManifest)
	http.HandleFunc("/sw.js", handleServiceWorker)
	http.HandleFunc("/icon.svg", handleIcon)

	webHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pDomain := config.PanelDomain
		nDomain := config.MasterDomain
		mu.Unlock()

		if pDomain != "" && nDomain != "" && pDomain != nDomain {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if strings.EqualFold(host, nDomain) {
				http.NotFound(w, r)
				return
			}
		}
		http.DefaultServeMux.ServeHTTP(w, r)
	})

	if isMasterTLS && tlsConfig != nil {
		displayDomain := panelDomain
		if displayDomain == "" {
			displayDomain = nodeDomain
		}
		log.Printf("🚀 控制面板启动 (自动安全 HTTPS): https://%s", displayDomain)
		server := &http.Server{
			Addr:      ":443",
			TLSConfig: tlsConfig,
			Handler:   webHandler,
		}
		log.Fatal(server.ListenAndServeTLS("", "")) 
	} else {
		log.Printf("🚀 控制面板启动 (普通 HTTP): http://localhost%s", WebPort)
		server := &http.Server{
			Addr:    WebPort,
			Handler: webHandler,
		}
		log.Fatal(server.ListenAndServe())
	}
}

// 每日流量统计定期刷盘
func flushDailyStats() {
	if db == nil {
		return
	}
	tx := atomic.SwapInt64(&dailyTxBuf, 0)
	rx := atomic.SwapInt64(&dailyRxBuf, 0)
	if tx > 0 || rx > 0 {
		today := time.Now().Format("2006-01-02")
		_, err := db.Exec(`INSERT INTO daily_stats (date, tx, rx) VALUES (?, ?, ?)
			ON CONFLICT(date) DO UPDATE SET tx = tx + ?, rx = rx + ?`,
			today, tx, rx, tx, rx)
		if err != nil {
			log.Printf("⚠️ 保存每日流量快照失败: %v", err)
			atomic.AddInt64(&dailyTxBuf, tx)
			atomic.AddInt64(&dailyRxBuf, rx)
		}
	}
}

func handleGenAgentToken(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		w.Write([]byte(""))
		return
	}

	mu.Lock()
	if config.AgentTokens == nil {
		config.AgentTokens = make(map[string]string)
	}
	tk, exists := config.AgentTokens[name]
	if !exists {
		tk = generateUUID()
		config.AgentTokens[name] = tk
		saveConfigNoLock()
	}
	mu.Unlock()

	w.Write([]byte(tk))
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	wsMu.Lock()
	wsClients[conn] = true
	wsMu.Unlock()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			wsMu.Lock()
			delete(wsClients, conn)
			wsMu.Unlock()
			conn.Close()
			break
		}
	}
}

func broadcastLoop() {
	ticker := time.NewTicker(1 * time.Second)
	var lastTotalTx int64 = 0
	var lastTotalRx int64 = 0

	for range ticker.C {
		mu.Lock()
		var currentTx, currentRx int64
		var agentData []AgentStatusData
		var ruleData []RuleStatusData

		var agentList []*AgentInfo
		for _, a := range agents {
			agentList = append(agentList, a)
		}
		sort.Slice(agentList, func(i, j int) bool {
			return agentList[i].ConnectedAt.Before(agentList[j].ConnectedAt)
		})
		for _, a := range agentList {
			agentData = append(agentData, AgentStatusData{Name: a.Name, SysStatus: a.SysStatus})
		}
		
		for _, r := range rules {
			currentTx += r.TotalTx
			currentRx += r.TotalRx
			ruleData = append(ruleData, RuleStatusData{
				ID:        r.ID,
				Name:      r.Note,
                Group:     r.Group,
				Total:     r.TotalTx + r.TotalRx,
				Tx:        r.TotalTx,
				Rx:        r.TotalRx,
				UserCount: r.UserCount,
				Limit:     r.TrafficLimit,
				Status:    r.TargetStatus,
				Latency:   r.TargetLatency,
			})
		}
		mu.Unlock()

		var logData []OpLog
		if db != nil {
			lRows, err := db.Query("SELECT time, ip, action, msg FROM logs ORDER BY id DESC LIMIT 15")
			if err == nil {
				for lRows.Next() {
					var l OpLog
					lRows.Scan(&l.Time, &l.IP, &l.Action, &l.Msg)
					logData = append(logData, l)
				}
				lRows.Close()
			}
		}

		var speedTx int64 = 0
		var speedRx int64 = 0
		if lastTotalTx != 0 || lastTotalRx != 0 {
			speedTx = currentTx - lastTotalTx
			speedRx = currentRx - lastTotalRx
		}
		if speedTx < 0 {
			speedTx = 0
		}
		if speedRx < 0 {
			speedRx = 0
		}
		lastTotalTx = currentTx
		lastTotalRx = currentRx

		wsMu.Lock()
		if len(wsClients) == 0 {
			wsMu.Unlock()
			continue
		}
		msg := WSMessage{
			Type: "stats",
			Data: WSDashboardData{
				TotalTraffic: currentTx + currentRx,
				SpeedTx:      speedTx,
				SpeedRx:      speedRx,
				Agents:       agentData,
				Rules:        ruleData,
				Logs:         logData,
			},
		}
		for client := range wsClients {
			if err := client.WriteJSON(msg); err != nil {
				client.Close()
				delete(wsClients, client)
			}
		}
		wsMu.Unlock()
	}
}

func handleAgentConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	var msg Message
	if err := dec.Decode(&msg); err != nil || msg.Type != "auth" {
		return
	}

	data, ok := msg.Payload.(map[string]interface{})
	if !ok {
		return
	}
	reqToken, _ := data["token"].(string)
	name, _ := data["name"].(string)

	mu.Lock()
	globalTk := config.AgentToken
	var agentTk string
	if config.AgentTokens != nil {
		agentTk = config.AgentTokens[name]
	}
	mu.Unlock()

	if reqToken == "" || name == "" {
		return
	}
	if (globalTk != "" && reqToken == globalTk) || (agentTk != "" && reqToken == agentTk) {
		// 认证通过
	} else {
		return // 认证失败
	}

	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	mu.Lock()
	if old, exists := agents[name]; exists {
		old.Conn.Close()
	}
	agents[name] = &AgentInfo{Name: name, RemoteIP: remoteIP, Conn: conn, ConnectedAt: time.Now()}
	mu.Unlock()
	log.Printf("Agent上线: %s", name)
	addSystemLog(remoteIP, "Agent 上线", fmt.Sprintf("节点 %s 已连接", name))
	sendTelegram(fmt.Sprintf("🟢 节点上线通知\n名称: %s", name))
	pushConfigToAll()

	for {
		var m Message
		if dec.Decode(&m) != nil {
			break
		}
		if m.Type == "stats" {
			handleStatsReport(m.Payload)
		}
		if m.Type == "health" {
			handleHealthReport(m.Payload)
		}
		if m.Type == "ping" {
			if status, ok := m.Payload.(string); ok {
				mu.Lock()
				if agent, exists := agents[name]; exists {
					agent.SysStatus = status
				}
				mu.Unlock()
			}
		}
	}
	mu.Lock()
	if curr, ok := agents[name]; ok && curr.Conn == conn {
		delete(agents, name)
		mu.Unlock()
		sendTelegram(fmt.Sprintf("🔴 节点下线通知\n名称: %s", name))
	} else {
		mu.Unlock()
	}
}

func handleStatsReport(payload interface{}) {
	d, _ := json.Marshal(payload)
	var reports []TrafficReport
	json.Unmarshal(d, &reports)

	mu.Lock()
	defer mu.Unlock()
	limitTriggered := false
	for _, rep := range reports {
		if strings.HasSuffix(rep.TaskID, "_entry") {
			rid := strings.TrimSuffix(rep.TaskID, "_entry")
			for i := range rules {
				if rules[i].ID == rid {
					rules[i].TotalTx += rep.TxDelta
					rules[i].TotalRx += rep.RxDelta
					rules[i].UserCount = rep.UserCount
					atomic.StoreInt32(&configDirty, 1)

					// 将增量数据记录到每日流量统计缓冲池中
					atomic.AddInt64(&dailyTxBuf, rep.TxDelta)
					atomic.AddInt64(&dailyRxBuf, rep.RxDelta)

					// --- 智能预警机制开始 ---
					limit := rules[i].TrafficLimit
					total := rules[i].TotalTx + rules[i].TotalRx
					if limit > 0 {
						pct := float64(total) / float64(limit)
						if pct >= 1.0 && !rules[i].Alert100 {
							rules[i].Alert100 = true
							sendTelegram(fmt.Sprintf("🚨 <b>流量耗尽熔断</b>\n\n规则：【%s】\n状态：已切断连接\n说明：流量达到 100%%，为了您的钱包安全，该端口已自动熔断！", rules[i].Note))
							limitTriggered = true
						} else if pct >= 0.95 && pct < 1.0 && !rules[i].Alert95 {
							rules[i].Alert95 = true
							sendTelegram(fmt.Sprintf("⚠️ <b>流量极高预警</b>\n\n规则：【%s】\n状态：即将熔断\n说明：流量已使用超过 95%%，请及时检查或重置流量！", rules[i].Note))
						} else if pct >= 0.80 && pct < 0.95 && !rules[i].Alert80 {
							rules[i].Alert80 = true
							sendTelegram(fmt.Sprintf("🔔 <b>流量使用预警</b>\n\n规则：【%s】\n状态：运行中\n说明：流量已使用超过 80%%。", rules[i].Note))
						}
					}
					// --- 智能预警机制结束 ---
					break
				}
			}
		}
	}
	if limitTriggered {
		go pushConfigToAll()
	}
}

func handleHealthReport(payload interface{}) {
	d, _ := json.Marshal(payload)
	var reports []HealthReport
	json.Unmarshal(d, &reports)
	mu.Lock()
	defer mu.Unlock()
	for _, rep := range reports {
		if strings.HasSuffix(rep.TaskID, "_exit") {
			rid := strings.TrimSuffix(rep.TaskID, "_exit")
			for i := range rules {
				if rules[i].ID == rid {
					rules[i].TargetStatus = (rep.Latency >= 0)
					rules[i].TargetLatency = rep.Latency
					break
				}
			}
		}
	}
}

func pushConfigToAll() {
	mu.Lock()
	tasksMap := make(map[string][]ForwardTask)
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if r.TrafficLimit > 0 && (r.TotalTx+r.TotalRx) >= r.TrafficLimit {
			continue
		}
		rawIPs := strings.Split(r.TargetIP, ",")
		var targetList []string
		for _, ip := range rawIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				targetList = append(targetList, fmt.Sprintf("%s:%s", ip, r.TargetPort))
			}
		}
		finalTargetStr := strings.Join(targetList, ",")

		lb := r.LBStrategy
		if lb == "" {
			lb = "random"
		}

		tasksMap[r.ExitAgent] = append(tasksMap[r.ExitAgent], ForwardTask{
			ID: r.ID + "_exit", Protocol: r.Protocol, Listen: ":" + r.BridgePort, Target: finalTargetStr, SpeedLimit: r.SpeedLimit, LBStrategy: lb,
		})
		if exit, ok := agents[r.ExitAgent]; ok {
			rip := exit.RemoteIP
			if strings.Contains(rip, ":") && !strings.Contains(rip, "[") {
				rip = "[" + rip + "]"
			}
			tasksMap[r.EntryAgent] = append(tasksMap[r.EntryAgent], ForwardTask{
				ID: r.ID + "_entry", Protocol: r.Protocol, Listen: ":" + r.EntryPort, Target: fmt.Sprintf("%s:%s", rip, r.BridgePort), SpeedLimit: r.SpeedLimit, LBStrategy: "rr",
			})
		}
	}
	activeAgents := make(map[string]*AgentInfo)
	for k, v := range agents {
		activeAgents[k] = v
	}
	mu.Unlock()
	for n, a := range activeAgents {
		t := tasksMap[n]
		if t == nil {
			t = []ForwardTask{}
		}
		go func(conn net.Conn, tasks []ForwardTask) {
			json.NewEncoder(conn).Encode(Message{Type: "update", Payload: tasks})
		}(a.Conn, t)
	}
}

// ================= WEB HANDLERS =================

func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(manifestJSON))
}

func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(serviceWorkerJS))
}

func handleIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
		<rect width="512" height="512" fill="#6366f1"/>
		<text x="50%" y="50%" dominant-baseline="central" text-anchor="middle" fill="#ffffff" font-family="system-ui, sans-serif" font-size="130" font-weight="bold" letter-spacing="4">Relay</text>
	</svg>`
	w.Write([]byte(svg))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	al := make([]AgentInfo, 0)
	for _, a := range agents {
		al = append(al, *a)
	}
	sort.Slice(al, func(i, j int) bool {
		return al[i].ConnectedAt.Before(al[j].ConnectedAt)
	})
	var totalTraffic int64
	for _, r := range rules {
		totalTraffic += (r.TotalTx + r.TotalRx)
	}
	displayRules := make([]LogicalRule, len(rules))
	copy(displayRules, rules)
	mu.Unlock()

	sort.Slice(displayRules, func(i, j int) bool {
		if displayRules[i].Group == displayRules[j].Group {
			return displayRules[i].ID < displayRules[j].ID
		}
		return displayRules[i].Group < displayRules[j].Group
	})

	var displayLogs []OpLog
	if db != nil {
		rows, err := db.Query("SELECT time, ip, action, msg FROM logs ORDER BY id DESC LIMIT ?", MaxLogEntries)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l OpLog
				rows.Scan(&l.Time, &l.IP, &l.Action, &l.Msg)
				displayLogs = append(displayLogs, l)
			}
		}
	}

	// 提取近 30 天流量记录
	var dailyStats []DailyStat
	if db != nil {
		dsRows, err := db.Query("SELECT date, tx, rx FROM daily_stats ORDER BY date DESC LIMIT 30")
		if err == nil {
			defer dsRows.Close()
			for dsRows.Next() {
				var ds DailyStat
				dsRows.Scan(&ds.Date, &ds.Tx, &ds.Rx)
				dailyStats = append(dailyStats, ds)
			}
		}
	}
	// 将数据按时间顺序颠倒，方便图表显示
	for i, j := 0, len(dailyStats)-1; i < j; i, j = i+1, j-1 {
		dailyStats[i], dailyStats[j] = dailyStats[j], dailyStats[i]
	}
	// 如果没有任何记录，给一条今天的空数据防止前台报错
	if len(dailyStats) == 0 {
		dailyStats = append(dailyStats, DailyStat{Date: time.Now().Format("2006-01-02"), Tx: 0, Rx: 0})
	}
	dsBytes, _ := json.Marshal(dailyStats)

	mu.Lock()
	conf := config
	mu.Unlock()

	pStr := conf.AgentPorts
	if pStr == "" {
		pStr = "9999"
	}
	cleanPorts := make([]string, 0)
	for _, p := range strings.Split(pStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cleanPorts = append(cleanPorts, strings.TrimPrefix(p, ":"))
		}
	}

	data := struct {
		Agents         []AgentInfo
		Rules          []LogicalRule
		Logs           []OpLog
		User           string
		DownloadURL    string
		TotalTraffic   int64
		MasterDomain   string
		PanelDomain    string
		Config         AppConfig
		TwoFA          bool
		IsTLS          bool
		Ports          []string
		Version        string
		DailyStatsJSON template.JS
	}{al, displayRules, displayLogs, conf.WebUser, DownloadURL, totalTraffic, conf.MasterDomain, conf.PanelDomain, conf, conf.TwoFAEnabled, isMasterTLS, cleanPorts, AppVersion, template.JS(string(dsBytes))}

	t := template.New("dash").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"add":         func(a, b int64) int64 { return a + b },
		"percent": func(currTx, currRx, limit int64) float64 {
			if limit <= 0 {
				return 0
			}
			p := (float64(currTx+currRx) / float64(limit)) * 100
			if p > 100 {
				p = 100
			}
			return p
		},
		"formatSpeed": func(bytesPerSec int64) string {
			if bytesPerSec <= 0 {
				return "无限制"
			}
			return formatBytes(bytesPerSec) + "/s"
		},
	})
	t, _ = t.Parse(dashboardHtml)
	t.Execute(w, data)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		setup := config.IsSetup
		mu.Unlock()
		if !setup {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		mu.Lock()
		exp, ok := sessions[c.Value]
		mu.Unlock()
		if !ok || time.Now().After(exp) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	alreadySetup := config.IsSetup
	mu.Unlock()

	if alreadySetup {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		mu.Lock()
		config.WebUser = r.FormValue("username")
		salt := generateSalt()
		pwdHash := hashPassword(r.FormValue("password"), salt)
		config.WebPass = salt + "$" + pwdHash
		config.AgentToken = generateUUID()
		if config.AgentTokens == nil {
			config.AgentTokens = make(map[string]string)
		}
		config.IsSetup = true
		saveConfigNoLock()
		mu.Unlock()
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	t, _ := template.New("s").Parse(setupHtml)
	t.Execute(w, nil)
}


func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mu.Lock()
		isEnabled := config.TwoFAEnabled
		githubEnabled := config.GithubClientID != "" && config.GithubClientSecret != ""
		mu.Unlock()
		
		errCode := r.URL.Query().Get("err")
		errMsg := ""
		if errCode == "1" { errMsg = "账号或密码错误" }
		if errCode == "2" { errMsg = "2FA 动态码错误" }
		if errCode == "3" { errMsg = "GitHub 授权失败" }
		if errCode == "4" { errMsg = "该 GitHub 账号不在允许列表中" }

		t, _ := template.New("l").Parse(loginHtml)
		t.Execute(w, map[string]interface{}{
			"TwoFA": isEnabled,
			"GithubEnabled": githubEnabled,
			"Error": errMsg,
		})
		return
	}
	ip := getClientIP(r)
	if !checkLoginRateLimit(ip) {
		http.Error(w, "尝试次数过多", 429)
		return
	}
	mu.Lock()
	u, storedVal := config.WebUser, config.WebPass
	twoFAEnabled := config.TwoFAEnabled
	twoFASecret := config.TwoFASecret
	mu.Unlock()

	passMatch := false
	parts := strings.Split(storedVal, "$")
	if len(parts) == 2 {
		if r.FormValue("username") == u && hashPassword(r.FormValue("password"), parts[0]) == parts[1] {
			passMatch = true
		}
	} else if r.FormValue("username") == u && md5Hash(r.FormValue("password")) == storedVal {
		passMatch = true
	}

	if !passMatch {
		recordLoginFail(ip)
		http.Redirect(w, r, "/login?err=1", http.StatusSeeOther)
		return
	}

	if twoFAEnabled {
		if !totp.Validate(r.FormValue("code"), twoFASecret) {
			recordLoginFail(ip)
			http.Redirect(w, r, "/login?err=2", http.StatusSeeOther)
			return
		}
	}

	sid := make([]byte, 16)
	rand.Read(sid)
	sidStr := hex.EncodeToString(sid)
	mu.Lock()
	sessions[sidStr] = time.Now().Add(365 * 24 * time.Hour) 
	mu.Unlock()
	
	// 智能判断是否开启安全 Cookie
	secureCookie := isMasterTLS || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, Secure: secureCookie, MaxAge: 31536000, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ================= GITHUB OAUTH =================

func handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	clientID := config.GithubClientID
	mu.Unlock()

	if clientID == "" {
		http.Error(w, "GitHub OAuth 未配置", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s", clientID)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}

	mu.Lock()
	clientID := config.GithubClientID
	clientSecret := config.GithubClientSecret
	allowedUsersStr := config.GithubAllowedUsers
	mu.Unlock()

	tokenURL := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", clientID, clientSecret, code)
	req, _ := http.NewRequest("POST", tokenURL, nil)
	req.Header.Set("Accept", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tokenData)
	if tokenData.AccessToken == "" {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}

	userReq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userReq.Header.Set("Accept", "application/json")
	
	userResp, err := client.Do(userReq)
	if err != nil {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}
	defer userResp.Body.Close()

	var userData struct {
		Login string `json:"login"`
	}
	json.NewDecoder(userResp.Body).Decode(&userData)

	allowedUsers := strings.Split(allowedUsersStr, ",")
	isAllowed := false
	for _, u := range allowedUsers {
		if strings.TrimSpace(u) != "" && strings.EqualFold(strings.TrimSpace(u), userData.Login) {
			isAllowed = true
			break
		}
	}

	if !isAllowed || userData.Login == "" {
		ip := getClientIP(r)
		recordLoginFail(ip)
		http.Redirect(w, r, "/login?err=4", http.StatusSeeOther)
		return
	}

	sid := make([]byte, 16)
	rand.Read(sid)
	sidStr := hex.EncodeToString(sid)
	
	mu.Lock()
	sessions[sidStr] = time.Now().Add(365 * 24 * time.Hour)
	mu.Unlock()
	
	addLog(r, "系统登录", fmt.Sprintf("通过 GitHub 登录成功 (%s)", userData.Login))
	secureCookie := isMasterTLS || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, Secure: secureCookie, MaxAge: 31536000, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}


func handle2FAGenerate(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	u := config.WebUser
	mu.Unlock()
	key, _ := totp.Generate(totp.GenerateOpts{Issuer: "GoRelay-Pro", AccountName: u})
	var buf bytes.Buffer
	img, _ := qr.Encode(key.URL(), qr.M, qr.Auto)
	img, _ = barcode.Scale(img, 200, 200)
	png.Encode(&buf, img)
	resp := map[string]string{"secret": key.Secret(), "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())}
	json.NewEncoder(w).Encode(resp)
}

func handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct{ Secret, Code string }
	json.NewDecoder(r.Body).Decode(&req)
	if totp.Validate(req.Code, req.Secret) {
		mu.Lock()
		config.TwoFASecret = req.Secret
		config.TwoFAEnabled = true
		saveConfigNoLock()
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{"success": false})
	}
}

func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	config.TwoFAEnabled = false
	config.TwoFASecret = ""
	saveConfigNoLock()
	mu.Unlock()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleAddRule(w http.ResponseWriter, r *http.Request) {
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)
	lbStrategy := r.FormValue("lb_strategy")
	if lbStrategy == "" {
		lbStrategy = "random"
	}

	finalBridgePort := fmt.Sprintf("%d", 20000+time.Now().UnixNano()%30000)

	mu.Lock()
	rules = append(rules, LogicalRule{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Group:        r.FormValue("group"),
		Note:         r.FormValue("note"),
		EntryAgent:   r.FormValue("entry_agent"),
		EntryPort:    r.FormValue("entry_port"),
		ExitAgent:    r.FormValue("exit_agent"),
		TargetIP:     r.FormValue("target_ip"),
		TargetPort:   r.FormValue("target_port"),
		Protocol:     r.FormValue("protocol"),
		TrafficLimit: int64(limitGB * 1024 * 1024 * 1024),
		SpeedLimit:   int64(speedMB * 1024 * 1024),
		BridgePort:   finalBridgePort,
		LBStrategy:   lbStrategy,
	})
	saveConfigNoLock()
	mu.Unlock()
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleEditRule(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)
	lbStrategy := r.FormValue("lb_strategy")
	if lbStrategy == "" {
		lbStrategy = "random"
	}

	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Group = r.FormValue("group")
			rules[i].Note = r.FormValue("note")
			rules[i].EntryAgent = r.FormValue("entry_agent")
			rules[i].EntryPort = r.FormValue("entry_port")
			rules[i].ExitAgent = r.FormValue("exit_agent")
			rules[i].TargetIP = r.FormValue("target_ip")
			rules[i].TargetPort = r.FormValue("target_port")
			rules[i].Protocol = r.FormValue("protocol")
			newLimit := int64(limitGB * 1024 * 1024 * 1024)
			if rules[i].TrafficLimit != newLimit {
				rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
			}
			rules[i].TrafficLimit = newLimit
			rules[i].SpeedLimit = int64(speedMB * 1024 * 1024)
			rules[i].LBStrategy = lbStrategy
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleToggleRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Disabled = !rules[i].Disabled
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleResetTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].TotalTx, rules[i].TotalRx = 0, 0
			rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	go pushConfigToAll() 
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	var nr []LogicalRule
	for _, x := range rules {
		if x.ID != id {
			nr = append(nr, x)
		}
	}
	rules = nr
	saveConfigNoLock()
	mu.Unlock()
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleBatchRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	action := r.FormValue("action")
	ids := strings.Split(r.FormValue("ids"), ",")

	idMap := make(map[string]bool)
	for _, id := range ids {
		if id != "" {
			idMap[id] = true
		}
	}

	mu.Lock()
	if action == "delete" {
		var nr []LogicalRule
		for _, x := range rules {
			if !idMap[x.ID] {
				nr = append(nr, x)
			}
		}
		rules = nr
	} else if action == "enable" || action == "disable" || action == "reset" {
		for i := range rules {
			if idMap[rules[i].ID] {
				if action == "enable" {
					rules[i].Disabled = false
				}
				if action == "disable" {
					rules[i].Disabled = true
				}
				if action == "reset" {
					rules[i].TotalTx, rules[i].TotalRx = 0, 0
					rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
				}
			}
		}
	}
	saveConfigNoLock()
	mu.Unlock()

	go pushConfigToAll() 
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	if a, ok := agents[name]; ok {
		json.NewEncoder(a.Conn).Encode(Message{Type: "uninstall"})
	}
	mu.Unlock()
	http.Redirect(w, r, "/#dashboard", http.StatusSeeOther)
}

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
	config.TgBotToken = r.FormValue("tg_bot_token")
	config.TgChatID = r.FormValue("tg_chat_id")
	config.GithubClientID = r.FormValue("github_client_id")
	config.GithubClientSecret = r.FormValue("github_client_secret")
	config.GithubAllowedUsers = r.FormValue("github_allowed_users")
	
	if rd := r.FormValue("traffic_reset_day"); rd != "" {
		d, _ := strconv.Atoi(rd)
		if d < 0 || d > 31 { d = 0 }
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
		mu.Unlock() // 发生错误必须解锁
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
		rows, err := db.Query("SELECT time, ip, action, msg FROM logs ORDER BY id DESC")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l OpLog
				rows.Scan(&l.Time, &l.IP, &l.Action, &l.Msg)
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
	w.Write([]byte("ok"))
	go func() {
		time.Sleep(500 * time.Millisecond)
		doRestart()
	}()
}

func handleUpdateSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	if err := performSelfUpdate(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	go func() { time.Sleep(1 * time.Second); doRestart() }()
}

func handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	agent, ok := agents[name]
	mu.Unlock()
	if !ok {
		http.Error(w, "Agent not found", 404)
		return
	}
	json.NewEncoder(agent.Conn).Encode(Message{Type: "upgrade"})
	w.Write([]byte("ok"))
}

func handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(GithubLatestAPI)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"has_update": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"has_update": false})
		return
	}

	remoteVer := strings.TrimPrefix(data.TagName, "v")
	currentVer := strings.TrimPrefix(AppVersion, "v")

	hasUpdate := remoteVer != currentVer

	json.NewEncoder(w).Encode(map[string]interface{}{
		"has_update":     hasUpdate,
		"latest_version": data.TagName,
		"current":        AppVersion,
	})
}

func doRestart() {
	log.Println("🔄 接收到重启指令...")

	services := []string{"relay", "gorelay"}

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/systemd/system/%s.service", s)); err == nil {
				exec.Command("systemctl", "restart", s).Start()
				time.Sleep(1 * time.Second)
				os.Exit(0)
				return
			}
		}
	}

	if _, err := os.Stat("/etc/init.d"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/init.d/%s", s)); err == nil {
				exec.Command("rc-service", s, "restart").Start()
				time.Sleep(1 * time.Second)
				os.Exit(0)
				return
			}
		}
	}

	argv0, err := os.Executable()
	if err != nil {
		argv0 = os.Args[0]
	}
	os.Stdin = nil
	os.Stdout = nil
	os.Stderr = nil
	if runtime.GOOS == "windows" {
		os.Exit(0)
	} else {
		syscall.Exec(argv0, os.Args, os.Environ())
	}
}

// ================= AGENT CORE =================

func runAgent(name, masterAddr, token string) {
	for {
		var conn net.Conn
		var err error
		if useTLS {
			host, _, errHost := net.SplitHostPort(masterAddr)
			if errHost != nil {
				host = masterAddr
			}
			conn, err = tls.Dial("tcp", masterAddr, &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			})
		} else {
			conn, err = net.Dial("tcp", masterAddr)
		}
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		json.NewEncoder(conn).Encode(Message{Type: "auth", Payload: map[string]string{"name": name, "token": token}})
		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(1 * time.Second)
			h := time.NewTicker(10 * time.Second)
			defer t.Stop()
			defer h.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					var reps []TrafficReport
					agentTraffic.Range(func(k, v interface{}) bool {
						c := v.(*TrafficCounter)
						tx, rx := atomic.SwapInt64(&c.Tx, 0), atomic.SwapInt64(&c.Rx, 0)
						var uc int64 = 0
						if val, ok := agentUserCounts.Load(k); ok {
							uc = atomic.LoadInt64(val.(*int64))
						}
						if tx > 0 || rx > 0 || uc > 0 {
							reps = append(reps, TrafficReport{TaskID: k.(string), TxDelta: tx, RxDelta: rx, UserCount: uc})
						}
						return true
					})
					if len(reps) > 0 {
						json.NewEncoder(conn).Encode(Message{Type: "stats", Payload: reps})
					}
					json.NewEncoder(conn).Encode(Message{Type: "ping", Payload: getSysStatus()})
				case <-h.C:
					checkTargetHealth(conn)
				}
			}
		}()
		dec := json.NewDecoder(conn)
		for {
			var msg Message
			if dec.Decode(&msg) != nil {
				close(stop)
				conn.Close()
				break
			}
			if msg.Type == "uninstall" {
				json.NewEncoder(conn).Encode(Message{Type: "uninstalling"})
				doSelfUninstall()
				return
			}
			if msg.Type == "upgrade" {
				log.Println("收到更新指令，开始执行自我更新...")
				if err := performSelfUpdate(); err == nil {
					doRestart()
				} else {
					log.Printf("更新失败: %v", err)
				}
			}
			if msg.Type == "update" {
				d, _ := json.Marshal(msg.Payload)
				var tasks []ForwardTask
				json.Unmarshal(d, &tasks)
				active := make(map[string]bool)
				for _, t := range tasks {
					active[t.ID] = true
					activeTargets.Store(t.ID, t.Target)

					if oldVal, loaded := activeTasks.LoadOrStore(t.ID, t); loaded {
						oldTask := oldVal.(ForwardTask)
						if oldTask.Protocol != t.Protocol || oldTask.Listen != t.Listen || oldTask.SpeedLimit != t.SpeedLimit || oldTask.LBStrategy != t.LBStrategy {
							if closeFunc, ok := runningListeners.Load(t.ID); ok {
								closeFunc.(func())()
							}
							activeTasks.Store(t.ID, t)
							startProxy(t)
						}
					} else {
						agentTraffic.Store(t.ID, &TrafficCounter{})
						var uz int64 = 0
						agentUserCounts.Store(t.ID, &uz)
						startProxy(t)
					}
				}
				runningListeners.Range(func(k, v interface{}) bool {
					if !active[k.(string)] {
						v.(func())()
						runningListeners.Delete(k)
						agentTraffic.Delete(k)
						agentUserCounts.Delete(k)
						activeTargets.Delete(k)
						activeTasks.Delete(k)
						rrCounters.Delete(k)
					}
					return true
				})
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func doPing(address string) (int64, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = address
		} else {
			return -1, false
		}
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", host)
	}

	start := time.Now()
	err = cmd.Run()
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return -1, false
	}
	return latency, true
}

func checkTargetHealth(conn net.Conn) {
	var results []HealthReport
	activeTargets.Range(func(key, value interface{}) bool {
		checkMode := "tcp"
		if tVal, ok := activeTasks.Load(key); ok {
			if t, ok := tVal.(ForwardTask); ok {
				if t.Protocol == "udp" {
					checkMode = "ping"
				} else if t.Protocol == "both" {
					checkMode = "mixed"
				}
			}
		}

		targets := strings.Split(value.(string), ",")
		var bestLat int64 = -1

		for _, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			var success bool
			var lat int64

			if checkMode == "ping" {
				lat, success = doPing(target)
			} else if checkMode == "mixed" {
				start := time.Now()
				c, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err == nil {
					c.Close()
					lat = time.Since(start).Milliseconds()
					success = true
				} else {
					lat, success = doPing(target)
				}
			} else {
				start := time.Now()
				c, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err == nil {
					c.Close()
					lat = time.Since(start).Milliseconds()
					success = true
				} else {
					success = false
				}
			}

			if success {
				if bestLat == -1 || lat < bestLat {
					bestLat = lat
				}
				targetHealthMap.Store(target, lat)
			} else {
				targetHealthMap.Store(target, int64(-1))
			}
		}

		results = append(results, HealthReport{TaskID: key.(string), Latency: bestLat})
		return true
	})

	if len(results) > 0 {
		_ = json.NewEncoder(conn).Encode(Message{Type: "health", Payload: results})
	}
}

type IpTracker struct {
	mu    sync.Mutex
	refs  map[string]int
	count *int64
}

func (t *IpTracker) Add(addr string) {
	host, _, _ := net.SplitHostPort(addr)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refs[host]++
	if t.refs[host] == 1 {
		atomic.AddInt64(t.count, 1)
	}
}
func (t *IpTracker) Remove(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if count, exists := t.refs[host]; !exists || count <= 0 {
		return
	}

	t.refs[host]--

	if t.refs[host] <= 0 {
		delete(t.refs, host)
		if atomic.LoadInt64(t.count) > 0 {
			atomic.AddInt64(t.count, -1)
		}
	}
}

func startProxy(t ForwardTask) {
	var closers []func()
	var l sync.Mutex
	activeConns := make(map[net.Conn]struct{})
	closed := false
	closeAll := func() {
		l.Lock()
		defer l.Unlock()
		if closed {
			return
		}
		closed = true
		for _, f := range closers {
			f()
		}
		for c := range activeConns {
			c.Close()
		}
	}
	runningListeners.Store(t.ID, closeAll)
	v, _ := agentUserCounts.Load(t.ID)
	userCountPtr := v.(*int64)
	ipTracker := &IpTracker{refs: make(map[string]int), count: userCountPtr}

	if t.Protocol == "tcp" || t.Protocol == "both" {
		go func() {
			ln, err := net.Listen("tcp", t.Listen)
			if err != nil {
				return
			}
			l.Lock()
			closers = append(closers, func() { ln.Close() })
			l.Unlock()
			for {
				c, e := ln.Accept()
				if e != nil {
					break
				}
				l.Lock()
				if closed {
					c.Close()
					l.Unlock()
					continue
				}
				activeConns[c] = struct{}{}
				l.Unlock()
				ipTracker.Add(c.RemoteAddr().String())
				go func(conn net.Conn) {
					pipeTCP(conn, t.ID, t.SpeedLimit, t.LBStrategy)
					l.Lock()
					delete(activeConns, conn)
					l.Unlock()
					ipTracker.Remove(conn.RemoteAddr().String())
				}(c)
			}
		}()
	}
	if t.Protocol == "udp" || t.Protocol == "both" {
		go func() {
			addr, _ := net.ResolveUDPAddr("udp", t.Listen)
			ln, err := net.ListenUDP("udp", addr)
			if err != nil {
				return
			}
			l.Lock()
			closers = append(closers, func() { ln.Close() })
			l.Unlock()
			handleUDP(ln, t.ID, ipTracker, t.SpeedLimit, t.LBStrategy)
		}()
	}
}

func selectTarget(tid string, targets []string, strategy string) string {
	var valid []string
	var latencies []int64

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if v, ok := targetHealthMap.Load(t); ok {
			lat := v.(int64)
			if lat >= 0 {
				valid = append(valid, t)
				latencies = append(latencies, lat)
			}
		}
	}

	if len(valid) == 0 {
		valid = targets
		latencies = make([]int64, len(targets))
	}

	if len(valid) == 1 {
		return valid[0]
	}

	switch strategy {
	case "rr":
		v, _ := rrCounters.LoadOrStore(tid, new(uint64))
		c := v.(*uint64)
		idx := atomic.AddUint64(c, 1) % uint64(len(valid))
		return valid[idx]

	case "least_conn":
		var best string
		var minConn int64 = -1
		for _, t := range valid {
			v, _ := connCounters.LoadOrStore(t, new(int64))
			c := atomic.LoadInt64(v.(*int64))
			if minConn == -1 || c < minConn {
				minConn = c
				best = t
			}
		}
		if best == "" {
			best = valid[0]
		}
		return best

	case "fastest":
		var best string
		var minLat int64 = -1
		for i, t := range valid {
			lat := latencies[i]
			if minLat == -1 || lat < minLat {
				minLat = lat
				best = t
			}
		}
		if best == "" {
			best = valid[0]
		}
		return best

	default:
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(valid))))
		return valid[n.Int64()]
	}
}

func pipeTCP(src net.Conn, tid string, limit int64, strategy string) {
	defer src.Close()

	var targetStr string
	if v, ok := activeTargets.Load(tid); ok {
		targetStr = v.(string)
	} else {
		return
	}

	allTargets := strings.Split(targetStr, ",")
	bestTarget := selectTarget(tid, allTargets, strategy)

	vConn, _ := connCounters.LoadOrStore(bestTarget, new(int64))
	atomic.AddInt64(vConn.(*int64), 1)
	defer atomic.AddInt64(vConn.(*int64), -1)

	dst, err := net.DialTimeout("tcp", bestTarget, 2*time.Second)
	if err != nil {
		return
	}
	defer dst.Close()

	v, _ := agentTraffic.Load(tid)
	cnt := v.(*TrafficCounter)
	go copyCount(dst, src, &cnt.Tx, limit)
	copyCount(src, dst, &cnt.Rx, limit)
}

func handleUDP(ln *net.UDPConn, tid string, tracker *IpTracker, limit int64, strategy string) {
	udpSessions := &sync.Map{}
	v, _ := agentTraffic.Load(tid)
	cnt := v.(*TrafficCounter)

	go func() {
		for {
			time.Sleep(30 * time.Second)
			now := time.Now()
			udpSessions.Range(func(key, value interface{}) bool {
				s := value.(*udpSession)
				if now.Sub(s.lastActive) > 45*time.Second {
					s.conn.Close()
					udpSessions.Delete(key)
					tracker.Remove(key.(string))
				}
				return true
			})
		}
	}()

	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr
	for {
		n, srcAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			break
		}
		atomic.AddInt64(&cnt.Tx, int64(n))
		sAddr := srcAddr.String()
		val, ok := udpSessions.Load(sAddr)
		if ok {
			s := val.(*udpSession)
			s.lastActive = time.Now()
			s.conn.Write(buf[:n])
		} else {

			var currentTargetStr string
			if v, ok := activeTargets.Load(tid); ok {
				currentTargetStr = v.(string)
			} else {
				continue
			}
			targets := strings.Split(currentTargetStr, ",")

			bestTarget := selectTarget(tid, targets, strategy)

			vConn, _ := connCounters.LoadOrStore(bestTarget, new(int64))
			atomic.AddInt64(vConn.(*int64), 1)

			dstAddr, _ := net.ResolveUDPAddr("udp", bestTarget)
			newConn, err := net.DialUDP("udp", nil, dstAddr)
			if err != nil {
				atomic.AddInt64(vConn.(*int64), -1)
				continue
			}
			s := &udpSession{conn: newConn, lastActive: time.Now()}
			udpSessions.Store(sAddr, s)
			tracker.Add(sAddr)
			newConn.Write(buf[:n])
			go func(c *net.UDPConn, sa *net.UDPAddr, k string, bt string) {
				bPtr := bufPool.Get().(*[]byte)
				defer bufPool.Put(bPtr)
				b := *bPtr
				for {
					c.SetReadDeadline(time.Now().Add(65 * time.Second))
					m, _, e := c.ReadFromUDP(b)
					if e != nil {
						c.Close()
						udpSessions.Delete(k)
						tracker.Remove(k)
						atomic.AddInt64(vConn.(*int64), -1)
						break
					}
					ln.WriteToUDP(b[:m], sa)
					atomic.AddInt64(&cnt.Rx, int64(m))
				}
			}(newConn, srcAddr, sAddr, bestTarget)
		}
	}
}

func copyCount(dst io.Writer, src io.Reader, c *int64, limit int64) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			start := time.Now()
			nw, _ := dst.Write(buf[0:nr])
			if nw > 0 {
				atomic.AddInt64(c, int64(nw))
			}
			if limit > 0 {
				exp := time.Duration(1e9 * int64(nr) / limit)
				if act := time.Since(start); exp > act {
					time.Sleep(exp - act)
				}
			}
		}
		if err != nil {
			break
		}
	}
}

// ================= DATA PERSISTENCE =================

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
			case "agent_ports":
				config.AgentPorts = v
			case "master_domain":
				config.MasterDomain = v
			case "panel_domain":
				config.PanelDomain = v
			case "is_setup":
				config.IsSetup = (v == "true")
			case "tg_bot_token":
				config.TgBotToken = v
			case "tg_chat_id":
				config.TgChatID = v
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
			}
		}
	}

	if config.AgentTokens == nil {
		config.AgentTokens = make(map[string]string)
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

	_, _ = tx.Exec("DELETE FROM rules")
	for _, r := range lRules {
		d, a80, a95, a100 := 0, 0, 0, 0
		if r.Disabled { d = 1 }
		if r.Alert80 { a80 = 1 }
		if r.Alert95 { a95 = 1 }
		if r.Alert100 { a100 = 1 }

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

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("📢 正在安全关闭服务...")
		mu.Lock()
		for _, a := range agents {
			a.Conn.Close()
		}
		saveConfigNoLock()
		mu.Unlock()
		if db != nil {
			db.Close()
		}
		os.Exit(0)
	}()
}

func formatBytes(b int64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

const setupHtml = `<!DOCTYPE html>
<html lang="zh">
<head>
<title>初始化配置 - GoRelay Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#6366f1">
<style>
:root { --primary: #6366f1; --bg: #09090b; --card-bg: #18181b; --text: #fafafa; --text-sub: #a1a1aa; --border: #27272a; --input-bg: #27272a; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background-image: radial-gradient(circle at 50% -20%, #2e1065, transparent 40%); }
.card { background: var(--card-bg); padding: 40px; border-radius: 20px; box-shadow: 0 0 0 1px var(--border), 0 20px 40px -10px rgba(0,0,0,0.5); width: 100%; max-width: 380px; position: relative; overflow: hidden; }
.card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, rgba(99,102,241,0.5), transparent); }
h2 { text-align: center; margin: 0 0 8px 0; font-size: 24px; font-weight: 700; background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
p { text-align: center; color: var(--text-sub); margin-bottom: 32px; font-size: 13px; line-height: 1.6; }
.input-group { margin-bottom: 16px; position: relative; }
.input-group i { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); color: var(--text-sub); transition: .2s; font-size: 18px; }
input { width: 100%; padding: 12px 14px 12px 42px; border: 1px solid var(--border); border-radius: 10px; background: var(--input-bg); color: var(--text); outline: none; transition: .2s; box-sizing: border-box; font-size: 14px; }
input:focus { border-color: var(--primary); background: #000; box-shadow: 0 0 0 2px rgba(99,102,241,0.2); }
input:focus + i { color: var(--primary); }
button { width: 100%; padding: 12px; background: var(--primary); color: #fff; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; transition: .2s; margin-top: 10px; display: flex; align-items: center; justify-content: center; gap: 8px; }
button:hover { background: #4f46e5; }
</style>
</head>
<body>
<form class="card" method="POST">
    <h2>GoRelay Pro</h2>
    <p>欢迎使用，请配置初始管理员账户</p>
    <div class="input-group"><input name="username" placeholder="管理员用户名" required autocomplete="off"><i class="ri-user-line"></i></div>
    <div class="input-group"><input type="password" name="password" placeholder="登录密码" required><i class="ri-lock-password-line"></i></div>
    <button>完成初始化 <i class="ri-arrow-right-line"></i></button>
</form>
<script>if ('serviceWorker' in navigator) { window.addEventListener('load', () => { navigator.serviceWorker.register('/sw.js'); }); }</script>
</body>
</html>`

const loginHtml = `<!DOCTYPE html>
<html lang="zh">
<head>
<title>登录 - GoRelay Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#6366f1">
<script>
    const savedTheme = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', savedTheme);
</script>
<style>
:root { 
    --primary: #6366f1; 
    --bg: #f8fafc; 
    --card-bg: rgba(255, 255, 255, 0.85); 
    --text: #0f172a; 
    --text-sub: #64748b; 
    --border: #e2e8f0; 
    --input-bg: #f1f5f9;
    --input-focus: #ffffff;
    --card-border: rgba(0,0,0,0.08);
    --shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.1);
}
[data-theme="dark"] { 
    --bg: #09090b; 
    --card-bg: rgba(24, 24, 27, 0.6); 
    --text: #fafafa; 
    --text-sub: #a1a1aa; 
    --border: #27272a; 
    --input-bg: rgba(0, 0, 0, 0.2);
    --input-focus: rgba(0,0,0,0.4);
    --card-border: rgba(255,255,255,0.08);
    --shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.5);
}

body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; position: relative; transition: background 0.3s, color 0.3s; }
.bg-glow { position: absolute; width: 600px; height: 600px; background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%); top: -20%; left: 50%; transform: translateX(-50%); opacity: 0.6; pointer-events: none; }

.theme-toggle { position: absolute; top: 24px; right: 24px; width: 40px; height: 40px; border-radius: 12px; border: 1px solid var(--border); background: var(--card-bg); color: var(--text-sub); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: 0.2s; z-index: 100; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
.theme-toggle:hover { border-color: var(--primary); color: var(--primary); background: rgba(99, 102, 241, 0.1); transform: translateY(-2px); }

.card { background: var(--card-bg); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 48px 40px; border-radius: 24px; width: 100%; max-width: 340px; border: 1px solid var(--card-border); box-shadow: var(--shadow); position: relative; z-index: 10; transition: background 0.3s, border-color 0.3s, box-shadow 0.3s; }
.header { text-align: center; margin-bottom: 36px; }
.logo-icon { width: 56px; height: 56px; background: linear-gradient(135deg, #6366f1, #a855f7); border-radius: 16px; display: inline-flex; align-items: center; justify-content: center; font-size: 32px; color: white; box-shadow: 0 10px 20px -5px rgba(99,102,241,0.4); margin-bottom: 20px; }
.header h2 { margin: 0; font-size: 20px; font-weight: 600; color: var(--text); letter-spacing: -0.5px; }
.header p { margin: 6px 0 0; color: var(--text-sub); font-size: 13px; }

.input-box { margin-bottom: 16px; position: relative; }
.input-box i { position: absolute; left: 14px; top: 13px; color: var(--text-sub); font-size: 18px; transition: .2s; }
input { width: 100%; padding: 12px 14px 12px 44px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 12px; color: var(--text); font-size: 14px; outline: none; transition: .2s; box-sizing: border-box; }
input:focus { border-color: var(--primary); background: var(--input-focus); box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); }
input:focus + i { color: var(--primary); }

.submit-btn { width: 100%; padding: 12px; background: var(--primary); color: #fff; border: none; border-radius: 12px; font-size: 14px; font-weight: 500; cursor: pointer; transition: .2s; margin-top: 12px; display: flex; align-items: center; justify-content: center; gap: 8px; box-sizing: border-box; text-decoration: none; }
.submit-btn:hover { background: #4f46e5; transform: translateY(-1px); }
.github-btn { background: #24292f; margin-top: 0; }
.github-btn:hover { background: #1b1f23; }
.error-msg { background: rgba(239, 68, 68, 0.1); color: #ef4444; padding: 10px; border-radius: 8px; font-size: 12px; margin-bottom: 20px; text-align: center; border: 1px solid rgba(239, 68, 68, 0.2); display: flex; align-items: center; justify-content: center; gap: 6px; }
</style>
</head>
<body>
<div class="bg-glow"></div>

<button class="theme-toggle" onclick="toggleTheme()" title="切换主题">
    <i class="ri-moon-line" id="theme-icon"></i>
</button>

<form class="card" method="POST">
    <div class="header">
        <div class="logo-icon"><i class="ri-globe-line"></i></div>
        <h2>GoRelay Pro</h2>
        <p>安全内网穿透控制台</p>
    </div>
    {{if .Error}}<div class="error-msg"><i class="ri-error-warning-fill"></i> {{.Error}}</div>{{end}}
    
    <div class="input-box"><input name="username" placeholder="管理员账号" autocomplete="off"><i class="ri-user-3-line"></i></div>
    <div class="input-box"><input type="password" name="password" placeholder="登录密码"><i class="ri-lock-2-line"></i></div>
    {{if .TwoFA}}
    <div class="input-box"><input name="code" placeholder="2FA 动态验证码" pattern="[0-9]{6}" maxlength="6" style="letter-spacing: 4px; text-align: center; padding-left: 14px; font-weight: 600; font-family: monospace"><i class="ri-shield-keyhole-line" style="left: auto; right: 14px;"></i></div>
    {{end}}
    
    <button class="submit-btn">立即登录 <i class="ri-arrow-right-line"></i></button>

    {{if .GithubEnabled}}
    <div style="display: flex; align-items: center; margin: 20px 0; color: var(--text-sub); font-size: 12px;">
        <div style="flex: 1; height: 1px; background: var(--border);"></div>
        <div style="padding: 0 10px;">或</div>
        <div style="flex: 1; height: 1px; background: var(--border);"></div>
    </div>
    <a href="/oauth/github/login" class="submit-btn github-btn">
        <i class="ri-github-fill" style="font-size: 18px;"></i> 使用 GitHub 登录
    </a>
    {{end}}
</form>

<script>
    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('theme-icon').className = savedTheme === 'dark' ? 'ri-moon-line' : 'ri-sun-line';
    });
    function toggleTheme() {
        const html = document.documentElement;
        const curr = html.getAttribute('data-theme');
        const next = curr === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
        document.getElementById('theme-icon').className = next === 'dark' ? 'ri-moon-line' : 'ri-sun-line';
    }
</script>
<script>if ('serviceWorker' in navigator) { window.addEventListener('load', () => { navigator.serviceWorker.register('/sw.js'); }); }</script>
</body>
</html>`

const dashboardHtml = `
<!DOCTYPE html>
<html lang="zh" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>GoRelay Pro Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#6366f1">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
    --primary: #6366f1; --primary-hover: #4f46e5; --primary-light: rgba(99, 102, 241, 0.1);
    --bg-body: #f8fafc; --bg-sidebar: #ffffff; --bg-card: #ffffff; --bg-glass: rgba(255, 255, 255, 0.8);
    --text-main: #0f172a; --text-sub: #64748b; --text-inv: #ffffff;
    --border: #e2e8f0; --input-bg: #f1f5f9;
    --success: #10b981; --success-bg: rgba(16, 185, 129, 0.1); --success-text: #059669;
    --danger: #ef4444; --danger-bg: rgba(239, 68, 68, 0.1); --danger-text: #dc2626;
    --warning: #f59e0b; --warning-bg: rgba(245, 158, 11, 0.1); --warning-text: #d97706;
    --radius: 16px; --radius-sm: 8px;
    --shadow-card: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
    --sidebar-w: 260px;
    --font-main: 'Inter', sans-serif; --font-mono: 'JetBrains Mono', monospace;
    --trans: all 0.2s ease;
}
[data-theme="dark"] {
    --primary: #818cf8; --primary-hover: #6366f1; --primary-light: rgba(129, 140, 248, 0.15);
    --bg-body: #09090b; --bg-sidebar: #09090b; --bg-card: #18181b; --bg-glass: rgba(24, 24, 27, 0.7);
    --text-main: #fafafa; --text-sub: #a1a1aa;
    --border: #27272a; --input-bg: #27272a;
    --success-bg: rgba(16, 185, 129, 0.15); --success-text: #34d399;
    --danger-bg: rgba(239, 68, 68, 0.15); --danger-text: #f87171;
    --warning-bg: rgba(245, 158, 11, 0.15); --warning-text: #fbbf24;
    --shadow-card: 0 0 0 1px #27272a;
}

* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; outline: none; }
body { margin: 0; font-family: var(--font-main); background: var(--bg-body); color: var(--text-main); height: 100vh; display: flex; overflow: hidden; font-size: 14px; letter-spacing: -0.01em; transition: background 0.3s; }

.bg-decor { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; pointer-events: none; overflow: hidden; }
.shape { position: absolute; opacity: 0.15; }
[data-theme="dark"] .shape { opacity: 0.12; }
.shape-circle { border-radius: 50%; background: var(--primary); }
.shape-star { background: var(--text-sub); clip-path: polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%); }

.s1 { top: 10%; left: 5%; width: 300px; height: 300px; background: linear-gradient(45deg, var(--primary), var(--success)); filter: blur(60px); opacity: 0.2; }
.s2 { bottom: 15%; right: -5%; width: 400px; height: 400px; background: linear-gradient(to top, var(--primary), #8b5cf6); filter: blur(80px); opacity: 0.2; }

@keyframes float { 0% { transform: translateY(0px) rotate(0deg); } 50% { transform: translateY(-15px) rotate(5deg); } 100% { transform: translateY(0px) rotate(0deg); } }

::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-sub); }

.sidebar { width: var(--sidebar-w); background: var(--bg-sidebar); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; z-index: 50; padding: 24px 16px; }
.brand { display: flex; align-items: center; padding: 0 12px 24px 12px; font-size: 18px; font-weight: 700; gap: 12px; color: var(--text-main); }
.brand-icon { width: 32px; height: 32px; background: linear-gradient(135deg, #6366f1, #a855f7); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; font-size: 18px; box-shadow: 0 4px 12px -2px rgba(99,102,241,0.4); }

.menu { flex: 1; display: flex; flex-direction: column; gap: 4px; overflow-y: auto; }
.item { display: flex; align-items: center; padding: 10px 12px; color: var(--text-sub); cursor: pointer; border-radius: var(--radius-sm); transition: var(--trans); font-weight: 500; font-size: 13.5px; }
.item:hover { background: var(--input-bg); color: var(--text-main); }
.item.active { background: var(--input-bg); color: var(--text-main); font-weight: 600; }
.item.active i { color: var(--primary); }
.item i { margin-right: 10px; font-size: 18px; transition: var(--trans); }

.user-panel { margin-top: auto; padding-top: 16px; border-top: 1px solid var(--border); }
.user-card { display: flex; align-items: center; gap: 12px; padding: 12px; border-radius: 12px; background: var(--input-bg); transition: var(--trans); }
.avatar { width: 36px; height: 36px; background: linear-gradient(135deg, #3b82f6, #06b6d4); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 700; font-size: 14px; }
.btn-logout { background: transparent; border: none; color: var(--text-sub); cursor: pointer; margin-left: auto; padding: 8px; border-radius: 6px; display: flex; }
.btn-logout:hover { background: var(--border); color: var(--danger); }

.main { flex: 1; display: flex; flex-direction: column; position: relative; width: 100%; min-width: 0; }
.header { height: 72px; display: flex; align-items: center; justify-content: space-between; padding: 0 32px; z-index: 40; border-bottom: 1px solid transparent; transition: border-color 0.3s; }
.main.scrolled .header { border-bottom-color: var(--border); background: var(--bg-glass); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
.page-title { font-weight: 700; font-size: 20px; display: flex; align-items: center; gap: 10px; color: var(--text-main); }

.theme-toggle { width: 36px; height: 36px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--text-sub); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: var(--trans); }
.theme-toggle:hover { border-color: var(--primary); color: var(--primary); background: var(--primary-light); }

.content { flex: 1; padding: 32px; overflow-y: auto; overflow-x: hidden; scroll-behavior: smooth; }
.page { display: none; max-width: 1200px; margin: 0 auto; animation: fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.page.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

.card { background: var(--bg-card); padding: 24px; border-radius: var(--radius); box-shadow: var(--shadow-card); border: 1px solid transparent; margin-bottom: 24px; position: relative; transition: var(--trans); }
[data-theme="dark"] .card { border: 1px solid var(--border); }

h3 { margin: 0 0 20px 0; font-size: 15px; color: var(--text-main); font-weight: 600; display: flex; align-items: center; gap: 8px; letter-spacing: -0.01em; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 32px; }
.stat-item { padding: 20px; display: flex; flex-direction: column; gap: 4px; }
.stat-label { color: var(--text-sub); font-size: 13px; font-weight: 500; }
.stat-val { font-size: 28px; font-weight: 700; color: var(--text-main); font-family: var(--font-main); letter-spacing: -0.5px; margin: 6px 0; }
.stat-trend { font-size: 12px; display: flex; align-items: center; gap: 6px; font-weight: 500; color: var(--text-sub); opacity: 0.8; }
.stat-item i.bg-icon { position: absolute; right: 20px; bottom: 20px; font-size: 64px; opacity: 0.03; transform: rotate(-10deg); pointer-events: none; color: var(--text-main); }

.dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 24px; }
.chart-box { height: 320px; width: 100%; position: relative; }
@media (max-width: 1024px) { .dashboard-grid { grid-template-columns: 100%; } }

.table-container { overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); background: var(--bg-card); }
.table-container table { min-width: 600px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; }
th { text-align: left; padding: 14px 20px; color: var(--text-sub); font-size: 12px; font-weight: 600; background: var(--input-bg); border-bottom: 1px solid var(--border); }
td { padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--text-main); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--input-bg); }

/* 复选框美化 */
.custom-cb { display: flex; align-items: center; cursor: pointer; margin:0; }
.custom-cb input { position: absolute; opacity: 0; cursor: pointer; height: 0; width: 0; }
.checkmark { display: inline-block; width: 18px; height: 18px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 4px; transition: .2s; position: relative; }
.custom-cb:hover input ~ .checkmark { border-color: var(--primary); }
.custom-cb input:checked ~ .checkmark { background: var(--primary); border-color: var(--primary); }
.checkmark:after { content: ""; position: absolute; display: none; left: 6px; top: 2px; width: 4px; height: 9px; border: solid white; border-width: 0 2px 2px 0; transform: rotate(45deg); }
.custom-cb input:checked ~ .checkmark:after { display: block; }

.mini-chart-container { width: 100px; height: 32px; display: inline-block; vertical-align: middle; }
.speed-text { font-family: var(--font-mono); font-size: 12px; font-weight: 600; display: inline-block; width: 70px; text-align: right; }

.group-header { background: var(--input-bg); cursor: pointer; user-select: none; }
.group-header:hover { background: var(--border); }
.group-header td { padding: 10px 20px; font-weight: 600; color: var(--text-sub); font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase; }
.group-icon { transition: transform 0.2s; display: inline-block; margin-right: 6px; }
.group-collapsed .group-icon { transform: rotate(-90deg); }

.badge { padding: 3px 8px; border-radius: 99px; font-size: 11px; font-weight: 600; display: inline-flex; align-items: center; gap: 5px; border: 1px solid transparent; }
.badge.success { background: var(--success-bg); color: var(--success-text); border-color: rgba(16,185,129,0.1); }
.badge.danger { background: var(--danger-bg); color: var(--danger-text); border-color: rgba(239,68,68,0.1); }
.badge.warning { background: var(--warning-bg); color: var(--warning-text); border-color: rgba(245,158,11,0.1); }
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status-dot.pulse { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); animation: pulse 2s infinite; }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); } 70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); } 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); } }

.grid-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; align-items: end; }
.form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 8px; color: var(--text-sub); }
input, select { width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; background: var(--input-bg); color: var(--text-main); font-size: 14px; outline: none; transition: 0.2s; font-family: inherit; }
input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-light); background: var(--bg-card); }

.btn { background: var(--primary); color: #fff; border: none; padding: 10px 20px; border-radius: 10px; cursor: pointer; font-size: 13.5px; font-weight: 500; transition: 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 6px; text-decoration: none; }
.btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
.btn:active { transform: translateY(0); }
.btn.secondary { background: var(--bg-body); border: 1px solid var(--border); color: var(--text-main); }
.btn.secondary:hover { background: var(--input-bg); border-color: var(--text-sub); }
.btn.danger { background: var(--danger-bg); color: var(--danger-text); border: 1px solid rgba(239,68,68,0.1); }
.btn.danger:hover { background: var(--danger); color: #fff; border-color: transparent; }
.btn.warning { background: var(--warning-bg); color: var(--warning-text); border: 1px solid rgba(245,158,11,0.1); }
.btn.warning:hover { background: var(--warning); color: #fff; border-color: transparent; }
.btn.success { background: var(--success-bg); color: var(--success-text); border: 1px solid rgba(16,185,129,0.1); }
.btn.success:hover { background: var(--success); color: #fff; border-color: transparent; }
.btn.icon { padding: 0; width: 34px; height: 34px; font-size: 16px; border-radius: 8px; }

.progress { width: 100%; height: 5px; background: var(--border); border-radius: 10px; overflow: hidden; margin-top: 8px; }
.progress-bar { height: 100%; background: var(--primary); border-radius: 10px; transition: width 0.5s ease; }

.terminal-window { background: #0f172a; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b; font-family: var(--font-mono); }
.terminal-header { background: #1e293b; padding: 10px 16px; display: flex; align-items: center; gap: 6px; }
.dot { width: 10px; height: 10px; border-radius: 50%; }
.dot.red { background: #ef4444; } .dot.yellow { background: #f59e0b; } .dot.green { background: #10b981; }
.terminal-body { padding: 20px; color: #e2e8f0; font-size: 13px; line-height: 1.6; position: relative; }
.copy-overlay { position: absolute; top: 10px; right: 10px; }

.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); backdrop-filter: blur(4px); animation: fadeIn 0.2s; }
.modal-content { background: var(--bg-card); margin: 10vh auto; padding: 32px; border-radius: 20px; width: 90%; max-width: 500px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); border: 1px solid var(--border); transform: scale(0.95); animation: scaleIn 0.2s cubic-bezier(0.16, 1, 0.3, 1) forwards; position: relative; max-height: 80vh; overflow-y: auto; }
@keyframes scaleIn { to { transform: scale(1); opacity: 1; } }
.close-modal { position: absolute; right: 20px; top: 20px; font-size: 20px; cursor: pointer; color: var(--text-sub); transition: .2s; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: var(--input-bg); }
.close-modal:hover { color: var(--text-main); transform: rotate(90deg); }

.mobile-nav { display: none; }
@media (max-width: 768px) {
    .sidebar { display: none; }
    .header { padding: 0 20px; height: 60px; }
    .content { padding: 20px 16px 80px 16px; }
    .mobile-nav { display: flex; position: fixed; bottom: 0; left: 0; width: 100%; background: var(--bg-card); border-top: 1px solid var(--border); height: 60px; z-index: 100; justify-content: space-around; padding-bottom: env(safe-area-inset-bottom); align-items: center; }
    .nav-btn { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--text-sub); font-size: 10px; gap: 2px; height: 100%; }
    .nav-btn.active { color: var(--primary); }
    .nav-btn i { font-size: 20px; }
    .card { padding: 16px; }
    .batch-bar { flex-wrap: wrap; justify-content: center; padding: 12px; gap: 8px; }
    .batch-bar > span { width: 100%; text-align: center; }
    .batch-bar > div[style="flex:1"] { display: none; }
    .batch-bar .btn { flex: 1 1 calc(50% - 10px); padding: 10px 0; font-size: 12px; }
}

.toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(20px); background: #0f172a; color: #fff; padding: 10px 20px; border-radius: 50px; font-size: 13px; opacity: 0; visibility: hidden; transition: 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index: 2000; display: flex; align-items: center; gap: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); }
.toast.show { opacity: 1; visibility: visible; transform: translateX(-50%) translateY(0); bottom: 80px; }

/* 系统设置 Tab 样式 */
.settings-tabs { display: flex; gap: 8px; overflow-x: auto; padding: 0 24px 16px 24px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
.settings-tabs::-webkit-scrollbar { display: none; }
.settings-tab { padding: 8px 16px; font-size: 14px; font-weight: 500; color: var(--text-sub); cursor: pointer; border-radius: 8px; transition: 0.2s; display: flex; align-items: center; gap: 6px; white-space: nowrap; user-select: none; }
.settings-tab:hover { background: var(--input-bg); color: var(--text-main); }
.settings-tab.active { background: var(--primary-light); color: var(--primary); font-weight: 600; }
.settings-content { display: none; gap: 24px; grid-template-columns: 1fr; animation: fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.settings-content.active { display: grid; }

/* 批量操作浮动条 */
.batch-bar { display: none; background: var(--card-bg); backdrop-filter: blur(10px); padding: 12px 20px; border-radius: 12px; margin-bottom: 20px; align-items: center; gap: 12px; border: 1px solid var(--primary); box-shadow: 0 10px 25px -5px rgba(99,102,241,0.2); animation: fadeIn 0.3s; }
.batch-bar.active { display: flex; }
</style>
</head>
<body>

<div class="bg-decor">
    <div class="shape shape-circle s1"></div>
    <div class="shape shape-circle s2"></div>
    
    <div class="shape shape-star" style="top: 15%; right: 10%; width: 30px; height: 30px; animation: float 6s ease-in-out infinite;"></div>
    <div class="shape shape-circle" style="bottom: 25%; left: 15%; width: 40px; height: 40px; border: 3px solid var(--primary); background: transparent; animation: float 8s ease-in-out infinite reverse;"></div>
    <div class="shape" style="top: 35%; left: 45%; width: 25px; height: 25px; background: var(--warning); border-radius: 6px; transform: rotate(45deg); animation: float 7s ease-in-out infinite 1s;"></div>
    <div class="shape shape-circle" style="top: 60%; right: 25%; width: 20px; height: 20px; background: var(--success); animation: float 5s ease-in-out infinite 2s;"></div>
    <div class="shape" style="bottom: 10%; right: 40%; width: 35px; height: 35px; border: 3px solid var(--text-sub); background: transparent; transform: rotate(15deg); animation: float 9s ease-in-out infinite;"></div>
</div>

<div id="toast" class="toast"><i id="t-icon"></i><span id="t-msg"></span></div>

<div class="sidebar">
    <div class="brand"><div class="brand-icon"><i class="ri-globe-line"></i></div> GoRelay Pro</div>
    <div class="menu">
        <div class="item active" onclick="nav('dashboard',this)"><i class="ri-dashboard-line"></i> 概览监控</div>
        <div class="item" onclick="nav('rules',this)"><i class="ri-route-line"></i> 转发管理</div>
        <div class="item" onclick="nav('deploy',this)"><i class="ri-server-line"></i> 节点部署</div>
        <div class="item" onclick="nav('logs',this)"><i class="ri-file-list-2-line"></i> 系统日志</div>
        <div class="item" onclick="nav('settings',this)">
            <i class="ri-settings-4-line"></i> 系统设置
            <span id="settings-badge" class="status-dot pulse" style="background:var(--danger);display:none;margin-left:auto"></span>
        </div>
    </div>
    <div class="user-panel">
        <div class="user-card">
            <div class="avatar">{{printf "%.1s" .User}}</div>
            <div style="flex:1;overflow:hidden">
                <div style="font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{{.User}}</div>
                <div style="font-size:11px;color:var(--text-sub)">管理员</div>
            </div>
            <a href="/logout" class="btn-logout"><i class="ri-logout-box-r-line"></i></a>
        </div>
    </div>
</div>

<div class="main">
    <header class="header">
        <div class="page-title"><span id="page-text">仪表盘</span></div>
        <div style="display:flex;gap:12px;align-items:center">
            <a href="https://github.com/jinhuaitao/relay" target="_blank" class="theme-toggle" title="GitHub"><i class="ri-github-line"></i></a>
            <button class="theme-toggle" onclick="toggleTheme()"><i class="ri-moon-line" id="theme-icon"></i></button>
        </div>
    </header>

    <div class="content" onscroll="document.querySelector('.main').classList.toggle('scrolled', this.scrollTop > 10)">
        <div id="dashboard" class="page active">
            <div class="stats-grid">
                <div class="card stat-item">
                    <div class="stat-label">累计总流量</div>
                    <div class="stat-val" id="stat-total-traffic" style="color:#818cf8">{{formatBytes .TotalTraffic}}</div>
                    <div class="stat-trend"><i class="ri-database-2-line"></i> 数据中继总量</div>
                    <i class="ri-exchange-line bg-icon"></i>
                </div>
                <div class="card stat-item">
                    <div class="stat-label">实时下载 (Rx)</div>
                    <div class="stat-val" id="speed-rx" style="color:#06b6d4">0 B/s</div>
                    <div class="stat-trend"><i class="ri-arrow-down-circle-line"></i> 当前下行带宽</div>
                    <i class="ri-download-cloud-2-line bg-icon"></i>
                </div>
                <div class="card stat-item">
                    <div class="stat-label">实时上传 (Tx)</div>
                    <div class="stat-val" id="speed-tx" style="color:#8b5cf6">0 B/s</div>
                    <div class="stat-trend"><i class="ri-arrow-up-circle-line"></i> 当前上行带宽</div>
                    <i class="ri-upload-cloud-2-line bg-icon"></i>
                </div>
                <div class="card stat-item">
                    <div class="stat-label">节点状态</div>
                    <div class="stat-val" style="color:#10b981">{{len .Agents}} <span style="font-size:16px;color:var(--text-sub);font-weight:600">/ {{len .Rules}}</span></div>
                    <div class="stat-trend"><i class="ri-server-line"></i> 在线 / 规则总数</div>
                    <i class="ri-cpu-line bg-icon"></i>
                </div>
            </div>

            <div class="card" style="margin-bottom: 24px;">
                <h3><i class="ri-bar-chart-grouped-line" style="color:var(--success)"></i> 近 30 天流量消耗趋势</h3>
                <div class="chart-box" style="height: 250px; width: 100%; position: relative;"><canvas id="dailyChart"></canvas></div>
            </div>

            <div class="dashboard-grid">
                <div class="card">
                    <h3><i class="ri-pulse-line" style="color:var(--primary)"></i> 实时流量趋势</h3>
                    <div class="chart-box"><canvas id="trafficChart"></canvas></div>
                </div>
                <div class="card">
                    <h3><i class="ri-pie-chart-line" style="color:#f472b6"></i> 流量分布 (Top 5)</h3>
                    <div class="chart-box" style="display:flex;justify-content:center"><canvas id="pieChart"></canvas></div>
                </div>
            </div>

            <div class="card">
                <h3><i class="ri-table-line" style="color:var(--warning)"></i> 实时转发监控</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>规则名称</th>
                                <th style="width:25%">上传趋势 (Tx)</th>
                                <th style="width:25%">下载趋势 (Rx)</th>
                                <th style="width:15%">总流量</th>
                            </tr>
                        </thead>
                        <tbody id="rule-monitor-body">
    {{$currentGroup := "INIT_h7&^"}}
    {{range .Rules}}
    {{if ne .Group $currentGroup}}
    <tr class="group-header" onclick="toggleGroup(this)" data-group="{{.Group}}">
        <td colspan="4">
            <i class="ri-arrow-down-s-line group-icon"></i>
            <i class="ri-folder-3-fill" style="margin-right:4px"></i> 
            {{if .Group}}{{.Group}}{{else}}默认分组{{end}}
        </td>
    </tr>
    {{$currentGroup = .Group}}
    {{end}}
    <tr class="rule-row" data-group="{{.Group}}" id="rule-row-mon-{{.ID}}" style="{{if .Disabled}}opacity:0.6;filter:grayscale(1);{{end}}">
        <td>
            <div style="font-weight:600;font-size:13px;margin-bottom:2px">{{if .Note}}{{.Note}}{{else}}未命名规则{{end}}</div>
            <div style="font-size:11px;color:var(--text-sub);font-family:var(--font-mono)">{{printf "%.8s" .ID}}...</div>
        </td>
        <td><div class="mini-chart-container"><canvas id="chart-tx-{{.ID}}"></canvas></div><div class="speed-text" style="color:#8b5cf6" id="text-tx-{{.ID}}">0 B/s</div></td>
        <td><div class="mini-chart-container"><canvas id="chart-rx-{{.ID}}"></canvas></div><div class="speed-text" style="color:#06b6d4" id="text-rx-{{.ID}}">0 B/s</div></td>
        <td style="font-family:var(--font-mono);font-weight:600" id="text-total-{{.ID}}">{{formatBytes (add .TotalTx .TotalRx)}}</td>
    </tr>
    {{end}}
</tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="rules" class="page">
            <div class="card" style="padding: 16px; margin-bottom: 24px; border-top: 2px solid transparent; background-image: linear-gradient(var(--bg-card), var(--bg-card)), linear-gradient(90deg, #6366f1, #10b981, #f59e0b); background-origin: border-box; background-clip: padding-box, border-box;">
                <div style="display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: center;">
                    
                    <div style="display: flex; gap: 12px; align-items: center; flex: 1 1 260px; min-width: 240px;">
                        <div style="position: relative; flex: 1;">
                            <i class="ri-search-line" style="position: absolute; left: 14px; top: 50%; transform: translateY(-50%); color: var(--text-sub);"></i>
                            <input type="text" id="ruleSearch" placeholder="搜索规则..." style="width: 100%; padding-left: 36px; background: var(--bg-body); border: 1px solid transparent; border-radius: 8px;" onkeyup="filterRules()">
                        </div>
                        <select id="groupFilter" style="width: 130px; flex-shrink: 0; background: var(--bg-body); border: 1px solid transparent; border-radius: 8px; color: var(--text-main);" onchange="handleGroupSelect(this)">
                            <option value="">全部分组</option>
                            <option disabled>──────</option>
                            <option value="__NEW__">➕ 新建分组...</option>
                        </select>
                    </div>

                    <div style="display: flex; flex: 1 1 100px; justify-content: flex-end; min-width: 120px;">
                        <button class="btn" style="background: #6366f1; color: white; border-radius: 8px; font-weight: 500; width: 100%; max-width: 140px; justify-content: center; white-space: nowrap;" onclick="openAddModal()">
                            <i class="ri-add-line"></i> 添加规则
                        </button>
                    </div>
                    
                </div>
            </div>

            <div id="batch-bar" class="batch-bar">
                <span style="font-weight:600;font-size:14px;color:var(--primary)"><i class="ri-checkbox-multiple-line"></i> 已选择 <span id="sel-count" style="font-size:16px">0</span> 项</span>
                <button class="btn success" onclick="batchAction('enable')"><i class="ri-play-fill"></i> 启动</button>
                <button class="btn warning" onclick="batchAction('disable')"><i class="ri-pause-fill"></i> 暂停</button>
                <button class="btn secondary" onclick="batchAction('reset')"><i class="ri-refresh-line"></i> 重置流量</button>
                <div style="flex:1"></div>
                <button class="btn danger" onclick="batchAction('delete')"><i class="ri-delete-bin-line"></i> 批量删除</button>
            </div>

            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
                    <h3 style="margin:0"><i class="ri-list-settings-line"></i> 规则列表</h3>
                    <div style="display:flex; gap: 8px;">
                        <button class="btn secondary" style="font-size:13px; padding: 6px 12px;" onclick="location.href='/export_rules'" title="备份当前所有规则"><i class="ri-download-line"></i> 备份规则</button>
                        <button class="btn secondary" style="font-size:13px; padding: 6px 12px;" onclick="document.getElementById('import-rules-file').click()" title="恢复规则（覆盖现有）"><i class="ri-upload-line"></i> 恢复规则</button>
                        <input type="file" id="import-rules-file" style="display:none" accept=".json" onchange="importRules(this)">
                        <button class="btn icon secondary" onclick="refreshSection('rules', this)" title="局部刷新"><i class="ri-refresh-line"></i></button>
                    </div>
                </div>
                <div class="table-container" id="rules-container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:40px"><label class="custom-cb"><input type="checkbox" id="cb-all" onclick="toggleAllRules(this)"><span class="checkmark"></span></label></th>
                                <th>链路信息</th><th>目标地址 & 延迟</th><th>流量监控</th><th>状态</th><th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                        {{$currentGroup := "INIT_h7&^"}}
                        {{range .Rules}}
                        {{if ne .Group $currentGroup}}
                            <tr class="group-header" onclick="toggleGroup(this)" data-group="{{.Group}}">
                                <td colspan="6">
                                    <i class="ri-arrow-down-s-line group-icon"></i>
                                    <i class="ri-folder-3-fill" style="margin-right:4px"></i> 
                                    {{if .Group}}{{.Group}}{{else}}默认分组{{end}}
                                </td>
                            </tr>
                            {{$currentGroup = .Group}}
                        {{end}}
                        <tr class="rule-row" data-group="{{.Group}}" style="{{if .Disabled}}opacity:0.6;filter:grayscale(1);{{end}}">
                            <td onclick="event.stopPropagation()"><label class="custom-cb"><input type="checkbox" class="rule-cb" value="{{.ID}}" onchange="updateBatchUI()"><span class="checkmark"></span></label></td>
                            <td>
                                <div style="font-weight:600;font-size:14px;margin-bottom:4px">{{if .Note}}{{.Note}}{{else}}未命名规则{{end}}</div>
                                <div style="font-size:12px;color:var(--text-sub);display:flex;align-items:center;gap:6px">
                                    <span class="badge" style="background:var(--input-bg);color:var(--text-sub);border:1px solid var(--border)">{{.EntryAgent}}:{{.EntryPort}}</span> 
                                    <i class="ri-arrow-right-line" style="color:var(--text-sub);font-size:12px"></i> 
                                    <span class="badge" style="background:var(--input-bg);color:var(--text-sub);border:1px solid var(--border)">{{.ExitAgent}}</span>
                                </div>
                            </td>
                            <td>
                                <div style="font-family:var(--font-mono);font-size:13px">{{.TargetIP}}:{{.TargetPort}}</div>
                                <div style="font-size:12px;margin-top:4px;display:flex;align-items:center;gap:5px;color:var(--text-sub)" id="rule-latency-{{.ID}}"><i class="ri-loader-4-line ri-spin"></i> 检测中...</div>
                                <div style="font-size:11px;color:var(--primary);margin-top:4px"><i class="ri-guide-line"></i> {{if eq .LBStrategy "rr"}}轮询{{else if eq .LBStrategy "least_conn"}}最少连接{{else if eq .LBStrategy "fastest"}}最低延迟{{else}}随机负载{{end}}</div>
                            </td>
                            <td style="min-width:180px">
                                <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                                    <span><i class="ri-user-3-line"></i> <span id="rule-uc-{{.ID}}">{{.UserCount}}</span></span>
                                    <span id="rule-traffic-{{.ID}}" style="font-family:var(--font-mono);font-weight:600">{{formatBytes (add .TotalTx .TotalRx)}}</span>
                                </div>
                                {{if gt .TrafficLimit 0}}
                                <div class="progress"><div id="rule-bar-{{.ID}}" class="progress-bar" style="width:{{percent .TotalTx .TotalRx .TrafficLimit}}%"></div></div>
                                <div style="font-size:11px;color:var(--text-sub);margin-top:2px;text-align:right" id="rule-limit-text-{{.ID}}">限 {{formatBytes .TrafficLimit}}</div>
                                {{else}}
                                <div class="progress"><div class="progress-bar" style="width:100%;background:var(--success);opacity:0.3"></div></div>
                                {{end}}
                            </td>
                            <td>
                                {{if .Disabled}}<span class="badge" style="background:var(--input-bg);color:var(--text-sub)">已暂停</span>
                                {{else if and (gt .TrafficLimit 0) (ge (add .TotalTx .TotalRx) .TrafficLimit)}}<span class="badge danger">流量耗尽</span>
                                {{else}}<span class="badge success"><span class="status-dot pulse" id="rule-status-dot-{{.ID}}"></span> 运行中</span>{{end}}
                            </td>
                            <td>
                                <div style="display:flex;gap:6px">
                                    <button class="btn icon secondary" onclick="toggleRule('{{.ID}}')" title="切换状态">{{if .Disabled}}<i class="ri-play-fill" style="color:var(--success)"></i>{{else}}<i class="ri-pause-fill" style="color:var(--warning)"></i>{{end}}</button>
                                    <button class="btn icon secondary" onclick="openEdit('{{.ID}}','{{.Group}}','{{.Note}}','{{.EntryAgent}}','{{.EntryPort}}','{{.ExitAgent}}','{{.TargetIP}}','{{.TargetPort}}','{{.Protocol}}','{{.TrafficLimit}}','{{.SpeedLimit}}', '{{.LBStrategy}}')" title="编辑"><i class="ri-edit-line"></i></button>
                                    <button class="btn icon secondary" onclick="resetTraffic('{{.ID}}')" title="重置"><i class="ri-refresh-line"></i></button>
                                    <button class="btn icon danger" onclick="delRule('{{.ID}}')" title="删除"><i class="ri-delete-bin-line"></i></button>
                                </div>
                            </td>
                        </tr>
                        {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="deploy" class="page">
            <div class="card">
                <h3><i class="ri-terminal-box-line" style="color:var(--text-main)"></i> 节点安装向导</h3>
                <p style="color:var(--text-sub);font-size:14px;line-height:1.6;margin-bottom:24px">
                    请在您的 VPS 或服务器（支持 Linux）上执行以下命令以安装 Agent 客户端。通信 Token 将被<strong style="color:var(--primary)">全自动生成</strong>并注入到命令中。
                </p>
                
                <div style="background:var(--input-bg);padding:24px;border-radius:16px;border:1px solid var(--border)">
                    <div class="grid-form" style="margin-bottom:24px;grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                        <div class="form-group"><label>1. 节点名称</label><input id="agentName" value="Node-01"></div>
                        <div class="form-group"><label>2. 连接域名 (Node)</label><input value="{{.MasterDomain}}" disabled style="background:var(--bg-body);opacity:0.8;cursor:not-allowed" title="为了安全，Agent 节点已强制使用域名和 TLS 加密连接"></div>
                        <div class="form-group">
                            <label>3. 通信端口</label>
                            <select id="connPort">
                                {{range .Ports}}<option value="{{.}}">{{.}}</option>{{end}}
                                <option disabled>──────────</option>
                                <option disabled value="">(去设置页添加)</option>
                            </select>
                        </div>
                        <div class="form-group"><label>4. 架构</label><select id="archType"><option value="amd64">Linux AMD64 (x86_64)</option><option value="arm64">Linux ARM64 (aarch64)</option></select></div>
                    </div>
                    <button class="btn" onclick="genCmd()"><i class="ri-magic-line"></i> 生成安装命令</button>
                    
                    <div class="terminal-window" style="margin-top:24px">
                        <div class="terminal-header">
                            <div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div>
                            <span style="color:#64748b;font-size:12px;margin-left:auto"></span>
                        </div>
                        <div class="terminal-body">
                            <div class="copy-overlay"><button class="btn icon secondary" style="background:rgba(255,255,255,0.1);color:#fff;border:none" onclick="copyCmd()" title="复制"><i class="ri-file-copy-line"></i></button></div>
                            <span style="color:#10b981">root@server:~$</span> <span id="cmdText" style="opacity:0.8">请先点击上方按钮生成命令...</span><span style="animation:blink 1s infinite"></span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
                    <h3 style="margin:0"><i class="ri-server-line"></i> 在线节点状态</h3>
                    <button class="btn icon secondary" onclick="refreshSection('agents', this)" title="局部刷新"><i class="ri-refresh-line"></i></button>
                </div>
                <div class="table-container" id="agents-container">
                    {{if .Agents}}
                    <table>
                        <thead><tr><th>状态</th><th>节点名称</th><th>远程 IP</th><th>资源监控 (CPU/内存/硬盘)</th><th>操作</th></tr></thead>
                        <tbody>
                        {{range .Agents}}
                        <tr>
                            <td><span class="badge success"><span class="status-dot pulse"></span> 在线</span></td>
                            <td><div style="font-weight:600">{{.Name}}</div></td>
                            <td><span class="badge" style="font-family:var(--font-mono);background:var(--input-bg);color:var(--text-sub);cursor:pointer" onclick="copyText('{{.RemoteIP}}')">{{.RemoteIP}}</span></td>
                            
                            <td style="width:280px" id="sys-status-{{.Name}}">
                                <div style="display:flex; flex-direction:column; gap:6px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span style="font-size:10px; width:25px; color:var(--text-sub)">CPU</span>
                                        <div class="progress" style="margin:0; flex:1; height:4px"><div class="progress-bar" id="cpu-bar-{{.Name}}" style="width:0%; background:#10b981"></div></div>
                                        <span id="cpu-val-{{.Name}}" style="font-size:11px; font-family:var(--font-mono); width:35px; text-align:right">0.0%</span>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span style="font-size:10px; width:25px; color:var(--text-sub)">内存</span>
                                        <div class="progress" style="margin:0; flex:1; height:4px"><div class="progress-bar" id="mem-bar-{{.Name}}" style="width:0%; background:#3b82f6"></div></div>
                                        <span id="mem-val-{{.Name}}" style="font-size:11px; font-family:var(--font-mono); width:35px; text-align:right">0.0%</span>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span style="font-size:10px; width:25px; color:var(--text-sub)">硬盘</span>
                                        <div class="progress" style="margin:0; flex:1; height:4px"><div class="progress-bar" id="dsk-bar-{{.Name}}" style="width:0%; background:#fbbf24"></div></div>
                                        <span id="dsk-val-{{.Name}}" style="font-size:11px; font-family:var(--font-mono); width:35px; text-align:right">0.0%</span>
                                    </div>
                                </div>
                            </td>

                            <td>
                                <div style="display:flex;gap:6px">
                                    <button class="btn icon warning" onclick="updateAgent('{{.Name}}')" title="更新"><i class="ri-refresh-line"></i></button>
                                    <button class="btn icon danger" onclick="delAgent('{{.Name}}')" title="卸载"><i class="ri-delete-bin-line"></i></button>
                                </div>
                            </td>
                        </tr>
                        {{end}}
                        </tbody>
                    </table>
                    {{else}}
                    <div style="padding:48px 0;text-align:center;color:var(--text-sub);font-size:13px">
                        <i class="ri-ghost-line" style="font-size:32px;display:block;margin-bottom:12px;opacity:0.5"></i>
                        暂无在线节点，请在上方生成命令进行部署
                    </div>
                    {{end}}
                </div>
            </div>
        </div>

        <div id="logs" class="page">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px">
                    <h3><i class="ri-file-history-line"></i> 系统操作日志</h3>
                    <div style="display:flex; gap: 8px;">
                        <button class="btn danger" style="font-size:13px; padding: 6px 12px;" onclick="clearLogs()"><i class="ri-delete-bin-line"></i> 清空</button>
                        <a href="/export_logs" class="btn secondary" style="text-decoration:none;font-size:13px; padding: 6px 12px;"><i class="ri-download-line"></i> 导出</a>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead><tr><th>时间</th><th>IP 来源</th><th>操作类型</th><th>详情内容</th></tr></thead>
                        <tbody id="log-table-body">
                        {{range .Logs}}
                        <tr>
                            <td style="font-family:var(--font-mono);color:var(--text-sub)">{{.Time}}</td>
                            <td>{{.IP}}</td>
                            <td><span class="badge" style="background:var(--input-bg);color:var(--text-main);border:1px solid var(--border)">{{.Action}}</span></td>
                            <td style="color:var(--text-sub)">{{.Msg}}</td>
                        </tr>
                        {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="settings" class="page">
            <div class="card" style="max-width:800px; padding: 24px 0;">
                <h3 style="padding: 0 24px; margin-bottom: 20px;"><i class="ri-settings-line"></i> 系统全局配置</h3>
                
                <div class="settings-tabs">
                    <div class="settings-tab active" onclick="switchSettingsTab('tab-basic', this)"><i class="ri-global-line"></i> 基础网络</div>
                    <div class="settings-tab" onclick="switchSettingsTab('tab-auth', this)"><i class="ri-shield-keyhole-line"></i> 安全认证</div>
                    <div class="settings-tab" onclick="switchSettingsTab('tab-notify', this)"><i class="ri-notification-3-line"></i> 通知与任务</div>
                    <div class="settings-tab" onclick="switchSettingsTab('tab-system', this)"><i class="ri-dashboard-3-line"></i> 系统维护</div>
                </div>

                <form id="settingsForm" onsubmit="saveSettings(event)" style="padding: 0 24px;">
                    <div class="grid-form" style="grid-template-columns: 1fr; gap:0;">
                        
                        <div style="min-height: 420px;">

                        <div id="tab-basic" class="settings-content active">

                            <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px dashed var(--border);">
                                <h4 style="margin:0 0 10px 0;font-size:14px;"><i class="ri-plug-line"></i> Agent 监听端口</h4>
                                <div class="form-group" style="margin:0">
                                    <label style="font-weight:400;font-size:12px">Master 监听的端口 (逗号分隔，例如: 9999,10086)</label>
                                    <input name="agent_ports" value="{{if .Config.AgentPorts}}{{.Config.AgentPorts}}{{else}}9999{{end}}" placeholder="9999">
                                    <div style="font-size:12px;color:var(--warning-text);margin-top:6px;"><i class="ri-alert-line"></i> 修改后系统会自动重启生效</div>
                                </div>
                            </div>

                            <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);">
                                <h4 style="margin:0 0 16px 0;font-size:14px;"><i class="ri-route-line"></i> 网络与域名配置</h4>
                                <div class="grid-form" style="gap:16px;grid-template-columns: 1fr 1fr;">
                                    <div class="form-group">
                                        <label>面板访问域名 (Panel) <i class="ri-cloud-line" title="可套CDN开启小云朵，供浏览器访问" style="color:#3b82f6;cursor:help"></i></label>
                                        <input name="panel_domain" value="{{.PanelDomain}}" placeholder="例如: panel.yourdomain.com">
                                    </div>
                                    <div class="form-group">
                                        <label>节点通信域名 (Node) <i class="ri-server-line" title="必须解析真实IP(关闭云朵)，供Agent连接" style="color:#10b981;cursor:help"></i></label>
                                        <input name="master_domain" value="{{.MasterDomain}}" placeholder="例如: node.yourdomain.com">
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div id="tab-auth" class="settings-content">
                            <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);">
                                <h4 style="margin:0 0 16px 0;font-size:14px;color:#cbd5e1"><i class="ri-github-fill"></i> GitHub 一键登录配置</h4>
                                <div class="grid-form" style="gap:16px;grid-template-columns: 1fr 1fr;">
                                    <div class="form-group"><label>Client ID</label><input name="github_client_id" value="{{.Config.GithubClientID}}" placeholder="留空则禁用"></div>
                                    <div class="form-group"><label>Client Secret</label><input type="password" name="github_client_secret" value="{{.Config.GithubClientSecret}}" placeholder="输入 Secret"></div>
                                </div>
                                <div class="form-group" style="margin-top: 16px;">
                                    <label>允许登录的 GitHub 用户名 (必须填写，多账号用逗号分隔)</label>
                                    <input name="github_allowed_users" value="{{.Config.GithubAllowedUsers}}" placeholder="例如: yourname, admin123">
                                </div>
                                <div style="font-size:12px;color:var(--text-sub);margin-top:10px;">
                                    * 配置前需在 GitHub -> Developer Settings -> OAuth Apps 中创建一个应用。回调地址请填写: <br/>
                                    <code style="color:var(--primary)">http(s)://你的面板域名/oauth/github/callback</code>
                                </div>
                            </div>

                            <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                                <div>
                                    <h4 style="margin:0 0 4px 0;font-size:14px">双因素认证 (2FA)</h4>
                                    <div style="font-size:12px;color:var(--text-sub)">Google Authenticator 登录保护</div>
                                </div>
                                <div>
                                    {{if .Config.TwoFAEnabled}}
                                    <button type="button" class="btn danger" onclick="disable2FA()">关闭</button>
                                    {{else}}
                                    <button type="button" class="btn" onclick="enable2FA()">开启</button>
                                    {{end}}
                                </div>
                            </div>
                        </div>

                        <div id="tab-notify" class="settings-content">
                            <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);">
                                <h4 style="margin:0 0 16px 0;font-size:14px;color:#3b82f6"><i class="ri-telegram-fill"></i> Telegram 机器人与自动任务</h4>
                                <div class="grid-form" style="gap:16px;grid-template-columns: 1fr 1fr;">
                                    <div class="form-group"><label>Bot Token</label><input name="tg_bot_token" value="{{.Config.TgBotToken}}"></div>
                                    <div class="form-group"><label>Chat ID</label><input name="tg_chat_id" value="{{.Config.TgChatID}}"></div>
                                    <div class="form-group" style="grid-column: 1 / -1">
                                        <label>每月自动清零账单日 (1-31) <i class="ri-information-line" title="到达该日0点将自动重置所有流量统计" style="color:var(--text-sub)"></i></label>
                                        <input type="number" name="traffic_reset_day" value="{{.Config.TrafficResetDay}}" placeholder="填 0 或留空表示不开启自动重置">
                                        <div style="font-size:12px;color:var(--text-sub);margin-top:6px;">* 开启后将同时激活 TG 的 80% / 95% / 100% 流量阶梯预警功能。系统每周一凌晨会自动备份数据库到您的 TG 窗口。</div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div id="tab-system" class="settings-content">
                                
                                <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);">
                                    <h4 style="margin:0 0 10px 0;font-size:14px;"><i class="ri-lock-password-line"></i> 面板密码</h4>
                                    <div class="form-group" style="margin:0; display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                                        <input type="password" name="password" placeholder="留空则不修改当前密码">
                                    </div>
                                </div>

                                <div style="background:rgba(16,185,129,0.05);padding:20px;border-radius:12px;border:1px solid rgba(16,185,129,0.2);display:flex;justify-content:space-between;align-items:center;margin-top:16px;">
                                <div>
                                    <h4 style="margin:0 0 4px 0;font-size:14px;color:#10b981">系统更新</h4>
                                    <div style="font-size:12px;color:var(--text-sub)">当前: {{.Version}} <span id="new-version-text" style="color:#f59e0b;display:none;margin-left:8px;font-weight:600">发现新版本</span></div>
                                </div>
                                <div>
                                    <button type="button" class="btn success" onclick="updateSystem()" id="btn-update">检查更新</button>
                                </div>
                            </div>
                        </div>

                        </div> <div style="display:flex;gap:12px;border-top:1px solid var(--border);padding-top:24px;">
                            <button class="btn" style="flex:2;height:44px">保存配置</button>
                            <a href="/download_config" class="btn secondary" style="flex:1;height:44px;display:flex;" title="备份数据"><i class="ri-download-cloud-2-line"></i>备份</a>
                            
                            <button type="button" class="btn secondary" style="flex:1;height:44px" onclick="document.getElementById('restore-file').click()" title="恢复数据"><i class="ri-upload-cloud-2-line"></i>恢复</button>
                            <input type="file" id="restore-file" style="display:none" accept=".db" onchange="restoreConfig(this)">
                            
                            <button type="button" class="btn warning" style="flex:1;height:44px" onclick="restartService()" title="重启服务"><i class="ri-restart-line"></i>重启服务</button>
                        </div>

                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="mobile-nav">
    <div class="nav-btn active" onclick="nav('dashboard',this)"><i class="ri-dashboard-line"></i><span>概览</span></div>
    <div class="nav-btn" onclick="nav('rules',this)"><i class="ri-route-line"></i><span>规则</span></div>
    <div class="nav-btn" onclick="nav('deploy',this)"><i class="ri-server-line"></i><span>节点</span></div>
    <div class="nav-btn" onclick="nav('logs',this)"><i class="ri-file-list-2-line"></i><span>日志</span></div>
    <div class="nav-btn" onclick="nav('settings',this)"><i class="ri-settings-4-line"></i><span>设置</span></div>
</div>

<div id="addRuleModal" class="modal">
    <div class="modal-content" style="max-width: 540px; padding: 32px; border-radius: 16px;">
        <span class="close-modal" onclick="closeAddModal()"><i class="ri-close-line"></i></span>
        <h3 style="margin-top: 0; font-size: 18px; margin-bottom: 4px;">添加转发规则</h3>
        <p style="color: var(--text-sub); font-size: 13px; margin-bottom: 24px;">配置新的端口转发规则</p>
        
        <form action="/add" method="POST">
            <div class="grid-form" style="grid-template-columns: 1fr 1fr; gap: 20px;">
                <div class="form-group">
                    <label>规则名称</label>
                    <input name="note" placeholder="例如: Steam 加速" required style="background: var(--bg-body);">
                </div>
                <div class="form-group">
                    <label>分组 <span style="font-size:12px;color:var(--text-sub)">(请在顶部工具栏新建)</span></label>
                    <select name="group" id="add_group_select" style="background: var(--bg-body);">
                        <option value="">默认分组</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>入口节点</label>
                    <select name="entry_agent" style="background: var(--bg-body);">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select>
                </div>
                <div class="form-group">
                    <label>入口端口</label>
                    <input type="number" name="entry_port" placeholder="10000" required style="background: var(--bg-body);">
                </div>
                
                <div class="form-group">
                    <label>出口节点</label>
                    <select name="exit_agent" style="background: var(--bg-body);">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select>
                </div>
                <div class="form-group">
                    <label>协议</label>
                    <select name="protocol" style="background: var(--bg-body);"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select>
                </div>
                
                <div class="form-group">
                    <label>目标地址</label>
                    <input name="target_ip" placeholder="目标IP或域名" required style="background: var(--bg-body);">
                </div>
                <div class="form-group">
                    <label>目标端口</label>
                    <input type="number" name="target_port" placeholder="443" required style="background: var(--bg-body);">
                </div>
                
                <div class="form-group">
                    <label>流量限制 (GB)</label>
                    <input type="number" step="0.1" name="traffic_limit" placeholder="0 表示无限制" style="background: var(--bg-body);">
                </div>
                <div class="form-group">
                    <label>速度限制 (MB/S)</label>
                    <input type="number" step="0.1" name="speed_limit" placeholder="0 表示无限制" style="background: var(--bg-body);">
                </div>

                <div style="display: none;"><select name="lb_strategy"><option value="random">random</option></select></div>

                <div class="form-group" style="grid-column: 1/-1; display: flex; justify-content: flex-end; gap: 12px; margin-top: 10px;">
                    <button type="button" class="btn secondary" onclick="closeAddModal()" style="width: 100px; background: transparent; border: 1px solid var(--border);">取消</button>
                    <button class="btn" style="width: 120px; background: #6366f1;"><i class="ri-save-line"></i> 保存规则</button>
                </div>
            </div>
        </form>
    </div>
</div>

<div id="editModal" class="modal">
    <div class="modal-content">
        <span class="close-modal" onclick="closeEdit()"><i class="ri-close-line"></i></span>
        <h3 style="margin-top:0;font-size:18px">修改规则</h3>
        <form action="/edit" method="POST">
            <input type="hidden" name="id" id="e_id">
            <div class="grid-form" style="grid-template-columns: 1fr 1fr; gap:20px">
                <div class="form-group"><label>分组</label><select name="group" id="e_group"><option value="">默认分组</option></select></div>
                <div class="form-group"><label>备注</label><input name="note" id="e_note"></div>
                <div class="form-group"><label>入口节点</label><select name="entry_agent" id="e_entry">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group"><label>入口端口</label><input type="number" name="entry_port" id="e_eport"></div>
                <div class="form-group"><label>出口节点</label><select name="exit_agent" id="e_exit">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group" style="grid-column: 1/-1"><label>目标地址 (逗号分隔多IP)</label><input name="target_ip" id="e_tip"></div>
                <div class="form-group"><label>目标端口</label><input type="number" name="target_port" id="e_tport"></div>
                <div class="form-group">
                    <label>负载均衡策略</label>
                    <select name="lb_strategy" id="e_lb">
                        <option value="random">随机分配 (Random)</option>
                        <option value="rr">轮询分配 (Round Robin)</option>
                        <option value="least_conn">最少连接 (Least Conn)</option>
                        <option value="fastest">最低延迟 (Fastest Ping/TCP)</option>
                    </select>
                </div>
                <div class="form-group"><label>协议</label><select name="protocol" id="e_proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select></div>
                <div class="form-group"><label>限额 (GB)</label><input type="number" step="0.1" name="traffic_limit" id="e_limit"></div>
                <div class="form-group"><label>限速 (MB/s)</label><input type="number" step="0.1" name="speed_limit" id="e_speed"></div>
                <div class="form-group" style="grid-column: 1/-1;margin-top:10px"><button class="btn" style="width:100%;height:44px">保存修改</button></div>
            </div>
        </form>
    </div>
</div>

<div id="confirmModal" class="modal">
    <div class="modal-content" style="max-width:380px;text-align:center;padding:32px">
        <div style="font-size:48px;margin-bottom:16px;line-height:1" id="c_icon">⚠️</div>
        <h3 style="justify-content:center;margin-bottom:8px;font-size:18px" id="c_title">确认操作</h3>
        <p style="color:var(--text-sub);margin-bottom:24px;line-height:1.5" id="c_msg"></p>
        <div style="display:flex;gap:12px">
            <button class="btn secondary" style="flex:1" onclick="closeConfirm()">取消</button>
            <button id="c_btn" class="btn danger" style="flex:1">确认</button>
        </div>
    </div>
</div>

<div id="inputModal" class="modal">
    <div class="modal-content" style="max-width:380px;text-align:center;padding:32px">
        <div style="font-size:48px;margin-bottom:16px;line-height:1">🌐</div>
        <h3 style="justify-content:center;margin-bottom:8px;font-size:18px" id="i_title">输入信息</h3>
        <p style="color:var(--text-sub);margin-bottom:20px;line-height:1.5;font-size:13px" id="i_msg"></p>
        <div style="margin-bottom:24px">
            <input id="i_input" placeholder="" style="width:100%;text-align:center;font-family:var(--font-mono);font-size:15px;padding:12px;border-radius:10px;box-sizing:border-box;">
        </div>
        <div style="display:flex;gap:12px">
            <button class="btn secondary" style="flex:1" id="i_btn_cancel">取消</button>
            <button class="btn" style="flex:1" id="i_btn_confirm">确认</button>
        </div>
    </div>
</div>

<div id="twoFAModal" class="modal">
    <div class="modal-content" style="text-align:center;max-width:340px">
        <span class="close-modal" onclick="document.getElementById('twoFAModal').style.display='none'"><i class="ri-close-line"></i></span>
        <h3 style="justify-content:center">绑定 2FA</h3>
        <p style="font-size:13px;color:var(--text-sub);margin-bottom:20px">使用 Google Authenticator 扫描</p>
        <div style="background:#fff;padding:12px;border-radius:16px;display:inline-block;margin-bottom:20px">
            <img id="qrImage" style="width:160px;height:160px;display:block">
        </div>
        <input id="twoFACode" placeholder="输入 6 位验证码" style="text-align:center;letter-spacing:4px;font-size:18px;margin-bottom:20px;font-family:var(--font-mono)">
        <button class="btn" onclick="verify2FA()" style="width:100%">验证并开启</button>
    </div>
</div>

<script>
    var m_domain="{{.MasterDomain}}", dwUrl="{{.DownloadURL}}", is_tls={{.IsTLS}};
    var lastRuleStats = {}; 
    var ruleCharts = {}; 
    
    function createMiniChartConfig(color) {
        const ctxGrad = document.createElement('canvas').getContext('2d').createLinearGradient(0, 0, 0, 32);
        ctxGrad.addColorStop(0, color.replace(')', ', 0.3)').replace('rgb', 'rgba'));
        ctxGrad.addColorStop(1, color.replace(')', ', 0)').replace('rgb', 'rgba'));

        return {
            type: 'line',
            data: { labels: Array(15).fill(''), datasets: [{ data: Array(15).fill(0), borderColor: color, backgroundColor: ctxGrad, borderWidth: 1.5, pointRadius: 0, fill: true, tension: 0.4 }] },
            options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: {display: false}, tooltip: {enabled: false} }, scales: { x: {display: false}, y: {display: false, min: 0} }, elements: { line: { borderJoinStyle: 'round' } } }
        };
    }

    function nav(id, el) {
        document.querySelectorAll('.page').forEach(e => e.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        
        const titles = {'dashboard':'仪表盘', 'deploy':'节点部署', 'rules':'转发规则', 'logs':'系统日志', 'settings':'系统配置'};
        document.getElementById('page-text').innerText = titles[id];
        
        document.querySelectorAll('.sidebar .item').forEach(i => i.classList.remove('active'));
        if (el) el.classList.add('active');
        else { const t = document.querySelector('.sidebar .item[onclick*="'+id+'"]'); if(t) t.classList.add('active'); }
        
        document.querySelectorAll('.mobile-nav .nav-btn').forEach(b => b.classList.remove('active'));
        const mBtn = document.querySelector('.mobile-nav .nav-btn[onclick*="'+id+'"]');
        if(mBtn) mBtn.classList.add('active');

        if(location.hash !== '#'+id) { if(history.pushState) history.pushState(null,null,'#'+id); else location.hash = '#'+id; }
    }
    
    function initTab() { const hash = window.location.hash.substring(1); if(hash && document.getElementById(hash)) nav(hash); }
    initTab();

    function initTab() { const hash = window.location.hash.substring(1); if(hash && document.getElementById(hash)) nav(hash); }
    initTab();

    // ================== 将代码插入在这里 ==================
    // 系统设置 Tab 切换逻辑
    function switchSettingsTab(tabId, el) {
        // 移除所有 tab 的 active 状态
        document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
        // 隐藏所有内容区域
        document.querySelectorAll('.settings-content').forEach(c => c.classList.remove('active'));
        
        // 激活当前点击的 tab 和对应的内容区域
        el.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    }
    // ======================================================


    document.addEventListener('DOMContentLoaded', () => {
        const collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        collapsed.forEach(g => {
            // 【修改点】选择所有同名分组的头部（包括监控列表和规则列表）
            const headers = document.querySelectorAll('.group-header[data-group="'+g+'"]');
            headers.forEach(h => setGroupState(h, false));
        });
        checkUpdate();
    });

    function toggleGroup(header) {
        const isCurrentlyCollapsed = header.classList.contains('group-collapsed');
        const group = header.getAttribute('data-group');
        
        // 【修改点】同步切换整个页面中（即两个表格内）相同分组的状态
        const headers = document.querySelectorAll('.group-header[data-group="'+group+'"]');
        headers.forEach(h => setGroupState(h, isCurrentlyCollapsed)); 
        
        let collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        if (isCurrentlyCollapsed) { collapsed = collapsed.filter(i => i !== group); } 
        else { if(!collapsed.includes(group)) collapsed.push(group); }
        localStorage.setItem('collapsed_groups', JSON.stringify(collapsed));
    }

    function setGroupState(header, expand) {
        const group = header.getAttribute('data-group');
        const rows = Array.from(document.querySelectorAll('.rule-row')).filter(row => row.getAttribute('data-group') === group);
        if (!expand) { header.classList.add('group-collapsed'); rows.forEach(r => r.style.display = 'none'); } 
        else { header.classList.remove('group-collapsed'); rows.forEach(r => r.style.display = 'table-row'); }
    }

    function toggleAllRules(source) {
        const checkboxes = document.querySelectorAll('.rule-cb');
        for(let i=0; i<checkboxes.length; i++) {
            if(checkboxes[i].closest('tr').style.display !== 'none') {
                checkboxes[i].checked = source.checked;
            }
        }
        updateBatchUI();
    }

    function updateBatchUI() {
        const cbs = document.querySelectorAll('.rule-cb:checked');
        const bar = document.getElementById('batch-bar');
        document.getElementById('sel-count').innerText = cbs.length;
        if(cbs.length > 0) { bar.classList.add('active'); } else { bar.classList.remove('active'); document.getElementById('cb-all').checked = false; }
    }

    function batchAction(action) {
        const cbs = document.querySelectorAll('.rule-cb:checked');
        if(cbs.length === 0) return;
        let ids = [];
        cbs.forEach(cb => ids.push(cb.value));

        let actionName = action === 'enable' ? '启动' : action === 'disable' ? '暂停' : action === 'reset' ? '重置流量' : '删除';
        showConfirm("批量" + actionName, "确定要对选中的 <b>"+cbs.length+"</b> 项规则执行" + actionName + "吗？", action === 'delete' ? 'danger' : 'warning', () => {
            const formData = new URLSearchParams();
            formData.append('action', action);
            formData.append('ids', ids.join(','));

            fetch('/batch', { method: 'POST', body: formData, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
            .then(r => r.json()).then(d => {
                if(d.success) { showToast("操作成功", "success"); setTimeout(() => location.reload(), 800); }
            }).catch(() => showToast("操作失败", "warn"));
        });
    }

    function copyText(txt) {
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(txt).then(() => showToast("已复制", "success"));
        else {
            const ta = document.createElement("textarea"); ta.value = txt; ta.style.position="fixed"; ta.style.left="-9999px";
            document.body.appendChild(ta); ta.focus(); ta.select();
            try { document.execCommand('copy'); showToast("已复制", "success"); } catch(e) { showToast("复制失败", "warn"); }
            document.body.removeChild(ta);
        }
    }

    function restartService() {
        showConfirm("重启服务", "确定要重启面板服务吗？连接将短暂中断。", "warning", () => {
            fetch('/restart', {method: 'POST'}).then(() => {
                showToast("系统正在重启...", "warn");
                setTimeout(() => location.reload(), 3000);
            }).catch(() => { showToast("请求发送失败", "warn"); });
        });
    }

    function restoreConfig(input) {
        if (!input.files || input.files.length === 0) return;
        const file = input.files[0]; input.value = ''; 
        
        // 优化点 1 & 2 & 3：详细的风险阻断提示
        showConfirm("⚠️ 恢复数据警告", 
            "确定要用该备份覆盖当前配置吗？此操作不可逆！<br><br>" +
            "<div style='text-align:left; font-size:12px; color:var(--text-sub); background:var(--input-bg); padding:12px; border-radius:8px; border:1px solid var(--border);'>" +
            "<b>恢复后将发生以下变化：</b><br>" +
            "1. 面板将自动重启，<span style='color:var(--warning-text)'>当前登录状态会失效</span>。<br>" +
            "2. 若备份包含域名，请确保该域名<span style='color:var(--danger-text)'>已解析到本机最新 IP</span>，否则恢复后将无法打开网页。<br>" +
            "3. 节点的通信 Token 将回滚到备份时的状态。</div>", 
            "restore", () => {
                
            const formData = new FormData(); formData.append('db_file', file);
            fetch('/upload_config', { method: 'POST', body: formData }).then(r => r.json()).then(d => {
                if (d.success) { 
                    // 明确告知需要重新登录
                    showToast("恢复成功，重启并跳转中 (需重新登录)...", "success"); 
                    
                    fetch('/restart', {method: 'POST'}).finally(() => {
                        setTimeout(() => {
                            if (d.redirect_host && d.redirect_host !== location.hostname) {
                                // 自动跳转到新域名
                                window.location.href = "https://" + d.redirect_host;
                            } else {
                                // 如果没有域名，原地刷新，系统拦截未登录状态退回 login
                                location.reload();
                            }
                        }, 4000); 
                    });
                } else { showToast("恢复失败: " + (d.error || "未知错误"), "warn"); }
            }).catch(() => {
                // 如果后端重启太快导致请求被切断（Catch 触发），依然执行跳转
                showToast("系统正在重启中，准备刷新...", "success");
                setTimeout(() => location.reload(), 3000);
            });
        });
    }

    function importRules(input) {
        if (!input.files || input.files.length === 0) return;
        const file = input.files[0]; 
        input.value = ''; 
        
        showConfirm("警告：恢复规则", "确定要用该备份文件【完全覆盖】当前所有的转发规则吗？此操作不可逆！", "restore", () => {
            const formData = new FormData(); 
            formData.append('rules_file', file);
            
            fetch('/import_rules', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(d => {
                if (d.success) { 
                    showToast("规则恢复成功，已推送到节点", "success"); 
                    setTimeout(() => location.reload(), 1500); 
                } else { 
                    showToast("恢复失败: " + (d.error || "未知错误"), "warn"); 
                }
            }).catch(() => showToast("上传请求失败", "warn"));
        });
    }

    function saveSettings(e) {
        e.preventDefault(); 
        const form = e.target;
        const btn = form.querySelector('button');
        const oldText = btn.innerHTML;
        
        btn.disabled = true;
        btn.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> 保存中...';

        const formData = new URLSearchParams(new FormData(form));
        
        fetch('/update_settings', { 
            method: 'POST', 
            body: formData, 
            headers: {'Content-Type': 'application/x-www-form-urlencoded'} 
        })
        .then(r => r.json())
        .then(d => {
            if (d.success) {
                if (d.need_restart) {
                    if (d.redirect_host && d.redirect_host !== location.hostname) {
                        showToast("配置已保存，正在重启并自动申请证书...", "success");
                        setTimeout(() => {
                            window.location.href = "https://" + d.redirect_host + "/#settings";
                        }, 5000); 
                    } else {
                        showToast("关键配置已修改，系统正在自动重启...", "success");
                        setTimeout(() => location.reload(), 4000);
                    }
                } else {
                    showToast("配置已保存", "success");
                    setTimeout(() => {
                        btn.disabled = false;
                        btn.innerHTML = oldText;
                    }, 1000);
                }
            } else {
                showToast("保存失败", "warn");
                btn.disabled = false;
                btn.innerHTML = oldText;
            }
        }).catch(() => {
            showToast("请求失败，面板可能正在重启", "warn");
            setTimeout(() => location.reload(), 4000);
        });
    }

    function checkUpdate() {
        fetch('/check_update').then(r=>r.json()).then(d => {
            if(d.has_update) {
                const badge = document.getElementById('settings-badge'); if(badge) badge.style.display = 'inline-block';
                const txt = document.getElementById('new-version-text'); if(txt) { txt.style.display = 'inline'; txt.innerText = '发现新版本 ' + d.latest_version; }
                showToast("发现新版本 " + d.latest_version, "success");
            }
        });
    }

    function updateSystem() {
        showConfirm("系统更新", "下载新版本并重启面板吗？", "warning", () => {
            const btn = document.getElementById('btn-update'); btn.disabled = true; btn.innerText = '更新中...';
            fetch('/update_sys', {method: 'POST'}).then(r=>r.json()).then(d => {
                if(d.success) { showToast("更新成功，重启中...", "success"); setTimeout(() => location.reload(), 5000); } 
                else { showToast("更新失败: " + d.error, "warn"); btn.disabled = false; btn.innerText = '检查更新'; }
            }).catch(() => { showToast("请求失败", "warn"); btn.disabled = false; btn.innerText = '检查更新'; });
        });
    }

    function updateAgent(name) {
        showConfirm("更新节点", "确定要远程更新节点 <b>"+name+"</b> 吗？", "warning", () => {
            fetch('/update_agent?name='+name, {method: 'POST'}).then(r => { if(r.ok) showToast("指令已发送", "success"); else showToast("发送失败", "warn"); });
        });
    }

    function delAgent(name) { showConfirm("卸载节点", "节点 <b>"+name+"</b> 将自毁，确定吗？", "danger", () => location.href="/delete_agent?name="+name); }

    function toggleTheme() {
        const html = document.documentElement;
        const curr = html.getAttribute('data-theme');
        const next = curr === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
        updateChartTheme(next);
        document.getElementById('theme-icon').className = next === 'dark' ? 'ri-moon-line' : 'ri-sun-line';
    }
    const savedTheme = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', savedTheme);
    document.getElementById('theme-icon').className = savedTheme === 'dark' ? 'ri-moon-line' : 'ri-sun-line';

    function showToast(msg, type) {
        const box = document.getElementById('toast');
        const icon = document.getElementById('t-icon');
        document.getElementById('t-msg').innerText = msg;
        box.className = 'toast show';
        if(type === 'warn') { icon.className = 'ri-error-warning-fill'; icon.style.color = '#fbbf24'; }
        else if(type === 'success') { icon.className = 'ri-checkbox-circle-fill'; icon.style.color = '#34d399'; }
        else { icon.className = 'ri-information-fill'; icon.style.color = '#60a5fa'; }
        setTimeout(() => box.className = 'toast', 2500);
    }

    function showConfirm(title, msg, type, cb) {
        document.getElementById('c_title').innerText = title; document.getElementById('c_msg').innerHTML = msg;
        const btn = document.getElementById('c_btn'); const icon = document.getElementById('c_icon');
        if(type === 'danger') { btn.className = 'btn danger'; btn.innerText = '确认删除'; icon.innerText = '🗑️'; } 
        else if(type === 'restore') { btn.className = 'btn danger'; btn.innerText = '确认恢复'; icon.innerText = '⚠️'; }
        else if(type === 'warning') { btn.className = 'btn warning'; btn.innerText = '确认操作'; icon.innerText = '⚡'; }
        else { btn.className = 'btn'; btn.innerText = '确认执行'; icon.innerText = '✨'; }
        btn.onclick = function() { closeConfirm(); cb(); };
        document.getElementById('confirmModal').style.display = 'block';
    }
    function closeConfirm() { document.getElementById('confirmModal').style.display = 'none'; }
    
    function showInput(title, msg, placeholder) {
        return new Promise((resolve) => {
            document.getElementById('i_title').innerText = title;
            document.getElementById('i_msg').innerHTML = msg;
            const inputEl = document.getElementById('i_input');
            inputEl.placeholder = placeholder;
            inputEl.value = '';
            
            const modal = document.getElementById('inputModal');
            const btnConfirm = document.getElementById('i_btn_confirm');
            const btnCancel = document.getElementById('i_btn_cancel');
            
            const cleanup = () => {
                modal.style.display = 'none';
                btnConfirm.onclick = null;
                btnCancel.onclick = null;
                inputEl.onkeydown = null;
            };

            btnConfirm.onclick = () => {
                cleanup();
                resolve(inputEl.value.trim());
            };
            btnCancel.onclick = () => {
                cleanup();
                resolve(null);
            };
            
            inputEl.onkeydown = (e) => {
                if (e.key === 'Enter') btnConfirm.click();
            };
            
            modal.style.display = 'block';
            setTimeout(() => inputEl.focus(), 100); 
        });
    }
    
    async function genCmd() {
        const n = document.getElementById('agentName').value;
        if (!n) { showToast("请输入节点名称", "warn"); return; }
        
        const arch = document.getElementById('archType').value;
        const p = document.getElementById('connPort').value; 
        const finalDwUrl = dwUrl + "-linux-" + arch;
        
        let host = m_domain;
        if(!host) { 
            host = await showInput(
                "未配置域名 (降级 TCP)", 
                "请输入 Master 服务器的真实 IP 地址<br><span style='color:var(--warning-text);font-weight:600'>注：IPv6 请用中括号包裹，例如 [240e:8a::1]</span>", 
                "例如: 1.2.3.4 或 [240e::1]"
            );
            if(!host) return; 
        }
        
        try {
            document.getElementById('cmdText').innerText = "获取专属凭证中...";
            document.getElementById('cmdText').style.opacity = '0.5';
            
            let r = await fetch('/gen_agent_token?name=' + encodeURIComponent(n));
            let agentToken = await r.text();
            
            let cmd = 'curl -L -o /root/relay '+finalDwUrl+' && chmod +x /root/relay && /root/relay -service install -mode agent -name "'+n+'" -connect "'+host+':'+p+'" -token "'+agentToken+'"';
            if(is_tls) cmd += ' -tls';
            
            document.getElementById('cmdText').innerText = cmd;
            document.getElementById('cmdText').style.opacity = '1';
            showToast("命令已生成", "success");
        } catch(e) {
            document.getElementById('cmdText').innerText = "获取凭证失败，请重试";
            showToast("生成凭证失败", "warn");
        }
    }
    function copyCmd() { copyText(document.getElementById('cmdText').innerText); }

    function delRule(id) { showConfirm("删除规则", "端口将停止服务，确定删除吗？", "danger", () => location.href="/delete?id="+id); }
    function toggleRule(id) { location.href="/toggle?id="+id; }
    function resetTraffic(id) { showConfirm("重置流量", "确定要清零统计数据吗？", "warning", () => location.href="/reset_traffic?id="+id); }
	function clearLogs() {
        showConfirm("清空日志", "确定要清空所有系统操作日志吗？此操作不可逆！", "danger", () => {
            fetch('/clear_logs', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if(d.success) {
                    showToast("日志已清空", "success");
                    // 刷新当前页面和组件
                    setTimeout(() => location.reload(), 800);
                } else {
                    showToast("操作失败", "warn");
                }
            }).catch(() => showToast("请求发送失败", "warn"));
        });
    }

    function openEdit(id, group, note, entry, eport, exit, tip, tport, proto, limit, speed, lb) {
        if (group && group !== '') { addGroupToUI(group); }
        document.getElementById('e_id').value = id;
        document.getElementById('e_group').value = group;
        document.getElementById('e_note').value = note;
        document.getElementById('e_entry').value = entry;
        document.getElementById('e_eport').value = eport;
        document.getElementById('e_exit').value = exit;
        document.getElementById('e_tip').value = tip;
        document.getElementById('e_tport').value = tport;
        document.getElementById('e_proto').value = proto;
        document.getElementById('e_limit').value = (parseFloat(limit)/(1024*1024*1024)).toFixed(2);
        document.getElementById('e_speed').value = (parseFloat(speed)/(1024*1024)).toFixed(1);
        if(document.getElementById('e_lb')) document.getElementById('e_lb').value = lb || 'random';
        document.getElementById('editModal').style.display = 'block';
    }
    function closeEdit() { document.getElementById('editModal').style.display = 'none'; }
    
    function openEdit(id, group, note, entry, eport, exit, tip, tport, proto, limit, speed, lb) {
        // ... 原本 openEdit 的代码 ...
        document.getElementById('editModal').style.display = 'block';
    }
    function closeEdit() { document.getElementById('editModal').style.display = 'none'; }
    
    function openAddModal() { document.getElementById('addRuleModal').style.display = 'block'; }
    function closeAddModal() { document.getElementById('addRuleModal').style.display = 'none'; }

    let dynamicGroups = new Set();

    function handleGroupSelect(sel) {
        if (sel.value === '__NEW__') {
            showInput("新建分组", "请输入新分组的名称", "例如: 香港节点").then(val => {
                if (val && val.trim() !== '') {
                    addGroupToUI(val.trim());
                    sel.value = val.trim(); // 选中刚创建的分组
                    filterRules();
                } else {
                    sel.value = ""; // 如果取消或没填，退回全部分组
                    filterRules();
                }
            });
        } else {
            filterRules();
        }
    }

    // 搜索和分组过滤逻辑
    function filterRules() {
        const term = document.getElementById('ruleSearch') ? document.getElementById('ruleSearch').value.toLowerCase() : '';
        const grp = document.getElementById('groupFilter') ? document.getElementById('groupFilter').value : '';
        document.querySelectorAll('.rule-row').forEach(row => {
            const text = row.innerText.toLowerCase();
            const rowGrp = row.getAttribute('data-group') || '';
            const matchSearch = text.includes(term);
            const matchGrp = (grp === '' || grp === '__NEW__' || rowGrp === grp);
            row.style.display = (matchSearch && matchGrp) ? '' : 'none';
        });
    }

    // 将分组名称注入到各个下拉框中
    function addGroupToUI(g) {
        if (!g || dynamicGroups.has(g) || g === "INIT_h7&^") return;
        dynamicGroups.add(g);
        
        // 1. 注入到顶部过滤器 (插入到分割线之前)
        const filterEl = document.getElementById('groupFilter');
        if (filterEl) {
            const divider = filterEl.querySelector('option[disabled]');
            const opt1 = document.createElement('option');
            opt1.value = g; opt1.text = g;
            if (divider) { filterEl.insertBefore(opt1, divider); } 
            else { filterEl.appendChild(opt1); }
        }

        // 2. 注入到添加弹窗
        const addSel = document.getElementById('add_group_select');
        if (addSel) {
            const opt2 = document.createElement('option');
            opt2.value = g; opt2.text = g;
            addSel.appendChild(opt2);
        }

        // 3. 注入到编辑弹窗
        const editSel = document.getElementById('e_group');
        if (editSel) {
            const opt3 = document.createElement('option');
            opt3.value = g; opt3.text = g;
            editSel.appendChild(opt3);
        }
    }

    // 页面加载完毕后，处理折叠状态并自动抓取真实分组
    document.addEventListener('DOMContentLoaded', () => {
        const collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        collapsed.forEach(g => {
            const headers = document.querySelectorAll('.group-header[data-group="'+g+'"]');
            headers.forEach(h => setGroupState(h, false));
        });
        if (typeof checkUpdate === 'function') checkUpdate();
        
        // 提取并填充现有分组
        document.querySelectorAll('.rule-row').forEach(r => {
            const g = r.getAttribute('data-group');
            addGroupToUI(g);
        });
    });

    // 页面加载完毕后，自动抓取已存在的分组并填充下拉框
    document.addEventListener('DOMContentLoaded', () => {
        const groups = new Set();
        document.querySelectorAll('.rule-row').forEach(r => {
            const g = r.getAttribute('data-group');
            if (g && g !== "INIT_h7&^") groups.add(g);
        });
        
        const filterEl = document.getElementById('groupFilter');
        const dlistEl = document.getElementById('group-list');
        if (filterEl && dlistEl) {
            groups.forEach(g => {
                // 【修改这里】使用原生的 DOM API 添加，彻底避开引号和拼接问题
                let opt1 = document.createElement('option');
                opt1.value = g;
                opt1.text = g;
                filterEl.appendChild(opt1);

                let opt2 = document.createElement('option');
                opt2.value = g;
                dlistEl.appendChild(opt2);
            });
        }
    });
    
    // ======================================================

    window.onclick = function(e) { 
        if(e.target.className === 'modal') { 
            closeEdit(); 
            closeAddModal(); // <--- 记得在这个点击空白关闭事件里加上这句
            closeConfirm(); 
            document.getElementById('twoFAModal').style.display='none'; 
            const btnCancel = document.getElementById('i_btn_cancel');
            if(btnCancel && document.getElementById('inputModal').style.display === 'block') {
                btnCancel.click();
            }
        } 
    }
    

    var tempSecret = "";
    function enable2FA() { fetch('/2fa/generate').then(r=>r.json()).then(d => { tempSecret = d.secret; document.getElementById('qrImage').src = d.qr; document.getElementById('twoFAModal').style.display = 'block'; }); }
    function verify2FA() { fetch('/2fa/verify', {method:'POST', body:JSON.stringify({secret:tempSecret, code:document.getElementById('twoFACode').value})}).then(r=>r.json()).then(d => { if(d.success) { showToast("2FA 已开启", "success"); setTimeout(()=>location.reload(), 1000); } else showToast("验证码错误", "warn"); }); }
    function disable2FA() { showConfirm("关闭 2FA", "账户安全性将降低，确定吗？", "danger", () => { fetch('/2fa/disable').then(r=>r.json()).then(d => { if(d.success) location.reload(); }); }); }

    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = '#94a3b8';
    
    var ctx = document.getElementById('trafficChart').getContext('2d');
    var txGrad = ctx.createLinearGradient(0, 0, 0, 300);
    txGrad.addColorStop(0, 'rgba(139, 92, 246, 0.2)'); txGrad.addColorStop(1, 'rgba(139, 92, 246, 0)');
    
    var rxGrad = ctx.createLinearGradient(0, 0, 0, 300);
    rxGrad.addColorStop(0, 'rgba(6, 182, 212, 0.2)'); rxGrad.addColorStop(1, 'rgba(6, 182, 212, 0)');

    var chart = new Chart(ctx, {
        type: 'line',
        data: { labels: Array(30).fill(''), datasets: [ { label: 'Tx', data: Array(30).fill(0), borderColor: '#8b5cf6', backgroundColor: txGrad, borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 }, { label: 'Rx', data: Array(30).fill(0), borderColor: '#06b6d4', backgroundColor: rxGrad, borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 } ] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false, backgroundColor: 'rgba(15, 23, 42, 0.9)', titleColor: '#f8fafc', bodyColor: '#cbd5e1', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1, padding: 10, displayColors: true } }, scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: 'rgba(128, 128, 128, 0.06)', borderDash: [4, 4] }, ticks: { callback: v => formatBytes(v)+'/s', font: {size: 10}, maxTicksLimit: 5 } } }, interaction: { mode: 'nearest', axis: 'x', intersect: false } }
    });

    var ctxPie = document.getElementById('pieChart').getContext('2d');
    var pieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#818cf8', '#f472b6', '#fbbf24', '#34d399', '#60a5fa'], borderWidth: 0, hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, usePointStyle: true, padding: 20, font: {size: 11} } } }, cutout: '75%' }
    });

    // 初始化近 30 天流量柱状图
    var dailyStatsData = {{.DailyStatsJSON}};
    var ctxDaily = document.getElementById('dailyChart').getContext('2d');
    var dailyChart = new Chart(ctxDaily, {
        type: 'bar',
        data: {
            labels: dailyStatsData.map(d => d.Date.substring(5)),
            datasets: [
                { label: '上传 (Tx)', data: dailyStatsData.map(d => d.Tx), backgroundColor: '#8b5cf6', borderRadius: 4, barPercentage: 0.6 },
                { label: '下载 (Rx)', data: dailyStatsData.map(d => d.Rx), backgroundColor: '#06b6d4', borderRadius: 4, barPercentage: 0.6 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { 
                legend: { display: true, position: 'top', labels: {color: '#94a3b8', font: {size: 11}, usePointStyle: true, boxWidth: 8} }, 
                tooltip: { mode: 'index', intersect: false, backgroundColor: 'rgba(15, 23, 42, 0.9)', titleColor: '#f8fafc', bodyColor: '#cbd5e1', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1, padding: 10,
                    callbacks: { label: function(c) { return c.dataset.label + ': ' + formatBytes(c.raw); } } 
                } 
            },
            scales: { 
                x: { stacked: true, grid: {display: false}, ticks: {color: '#94a3b8'} }, 
                y: { stacked: true, grid: { color: 'rgba(128, 128, 128, 0.06)', borderDash: [4, 4] }, ticks: { color: '#94a3b8', callback: v => formatBytes(v), maxTicksLimit: 6 } } 
            }
        }
    });

    function updateChartTheme(theme) {
        const gridColor = theme === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';
        chart.options.scales.y.grid.color = gridColor; chart.update();
        if(dailyChart) { dailyChart.options.scales.y.grid.color = gridColor; dailyChart.update(); }
    }

    function formatBytes(b) {
        if(b==0) return "0 B";
        const u = 1024, i = Math.floor(Math.log(b)/Math.log(u));
        return parseFloat((b / Math.pow(u, i)).toFixed(2)) + " " + ["B","KB","MB","GB","TB"][i];
    }
    function formatSpeed(b) { if(b<=0) return "0 B/s"; return formatBytes(b)+"/s"; }

    function refreshSection(type, btn) {
        const icon = btn.querySelector('i');
        icon.classList.add('ri-spin');
        
        fetch(location.pathname)
            .then(res => res.text())
            .then(html => {
                const doc = new DOMParser().parseFromString(html, 'text/html');
                
                if (type === 'rules') {
                    const newContent = doc.getElementById('rules-container');
                    if (newContent) {
                        document.getElementById('rules-container').innerHTML = newContent.innerHTML;
                        const collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
                        collapsed.forEach(g => {
                            const header = document.querySelector('.group-header[data-group="'+g+'"]');
                            if(header) setGroupState(header, false); 
                        });
                        updateBatchUI();
                    }
                } else if (type === 'agents') {
                    const newContent = doc.getElementById('agents-container');
                    if (newContent) {
                        document.getElementById('agents-container').innerHTML = newContent.innerHTML;
                    }
                }
                showToast("刷新成功", "success");
            })
            .catch(err => {
                showToast("获取最新数据失败", "warn");
            })
            .finally(() => {
                setTimeout(() => icon.classList.remove('ri-spin'), 500);
            });
    }

    function connectWS() {
        const ws = new WebSocket((location.protocol==='https:'?'wss:':'ws:') + '//' + location.host + '/ws');
        ws.onmessage = function(e) {
            try {
                const msg = JSON.parse(e.data);
                if(msg.type === 'stats' && msg.data) {
                    const d = msg.data;
                    document.getElementById('stat-total-traffic').innerText = formatBytes(d.total_traffic);
                    document.getElementById('speed-rx').innerText = formatBytes(d.speed_rx) + '/s';
                    document.getElementById('speed-tx').innerText = formatBytes(d.speed_tx) + '/s';
                    
                    chart.data.datasets[0].data.push(d.speed_tx); chart.data.datasets[0].data.shift();
                    chart.data.datasets[1].data.push(d.speed_rx); chart.data.datasets[1].data.shift();
                    chart.update('none');

                    if (d.rules) {
                        const sortedRules = [...d.rules].sort((a,b) => b.total - a.total).slice(0, 5);
                        pieChart.data.labels = sortedRules.map(r => r.name || '未命名');
                        pieChart.data.datasets[0].data = sortedRules.map(r => r.total);
                        pieChart.update('none');
                        
                        const tbody = document.getElementById('rule-monitor-body');
                        if(document.getElementById('dashboard').classList.contains('active')) {
                            const activeIds = new Set();
                            d.rules.forEach(r => {
                                activeIds.add(r.id);
                                let stx = 0, srx = 0;
                                if (lastRuleStats[r.id]) { stx = r.tx - lastRuleStats[r.id].tx; srx = r.rx - lastRuleStats[r.id].rx; if(stx < 0) stx = 0; if(srx < 0) srx = 0; }
                                lastRuleStats[r.id] = {tx: r.tx, rx: r.rx};

                                let row = document.getElementById('rule-row-mon-' + r.id);
                                if (!row) {
                                    // 兼容免刷新添加新规则：动态插入
                                    row = tbody.insertRow(); 
                                    row.id = 'rule-row-mon-' + r.id;
                                    row.className = 'rule-row';
                                    row.setAttribute('data-group', r.group || '');
                                    row.innerHTML = '<td><div style="font-weight:600;font-size:13px;margin-bottom:2px">'+(r.name||'未命名')+'</div><div style="font-size:11px;color:var(--text-sub);font-family:var(--font-mono)">'+r.id.substring(0,8)+'...</div></td>'+
                                        '<td><div class="mini-chart-container"><canvas id="chart-tx-'+r.id+'"></canvas></div><div class="speed-text" style="color:#8b5cf6" id="text-tx-'+r.id+'">0 B/s</div></td>'+
                                        '<td><div class="mini-chart-container"><canvas id="chart-rx-'+r.id+'"></canvas></div><div class="speed-text" style="color:#06b6d4" id="text-rx-'+r.id+'">0 B/s</div></td>'+
                                        '<td style="font-family:var(--font-mono);font-weight:600" id="text-total-'+r.id+'">'+formatBytes(r.total)+'</td>';

                                    const ctxTx = document.getElementById('chart-tx-'+r.id).getContext('2d');
                                    const ctxRx = document.getElementById('chart-rx-'+r.id).getContext('2d');
                                    ruleCharts[r.id] = { tx: new Chart(ctxTx, createMiniChartConfig('#8b5cf6')), rx: new Chart(ctxRx, createMiniChartConfig('#06b6d4')) };
                                } else {
                                    document.getElementById('text-tx-'+r.id).innerText = formatSpeed(stx); 
                                    document.getElementById('text-rx-'+r.id).innerText = formatSpeed(srx); 
                                    document.getElementById('text-total-'+r.id).innerText = formatBytes(r.total);

                                    // 【核心修改】如果是后端模板预渲染出来的行，初次连接WS时需要初始化图表对象
                                    if (!ruleCharts[r.id]) {
                                        const ctxTx = document.getElementById('chart-tx-'+r.id).getContext('2d');
                                        const ctxRx = document.getElementById('chart-rx-'+r.id).getContext('2d');
                                        ruleCharts[r.id] = { tx: new Chart(ctxTx, createMiniChartConfig('#8b5cf6')), rx: new Chart(ctxRx, createMiniChartConfig('#06b6d4')) };
                                    }
                                }
                                const charts = ruleCharts[r.id];
                                if (charts) { charts.tx.data.datasets[0].data.push(stx); charts.tx.data.datasets[0].data.shift(); charts.tx.update('none'); charts.rx.data.datasets[0].data.push(srx); charts.rx.data.datasets[0].data.shift(); charts.rx.update('none'); }
                            });
                            
                            // 清理已被删除的规则所在的行
                            Array.from(tbody.children).forEach(tr => {
                                // 【核心修改】忽略分组标题行，防止被误删
                                if (tr.classList.contains('group-header')) return; 
                                
                                const id = tr.id.replace('rule-row-mon-', '');
                                if (id && !activeIds.has(id)) { 
                                    if(ruleCharts[id]) { ruleCharts[id].tx.destroy(); ruleCharts[id].rx.destroy(); delete ruleCharts[id]; } 
                                    tr.remove(); 
                                }
                            });
                        }
                        
                        d.rules.forEach(r => {
                            const traf = document.getElementById('rule-traffic-'+r.id); if(traf) traf.innerText = formatBytes(r.total);
                            const uc = document.getElementById('rule-uc-'+r.id); if(uc) uc.innerText = r.uc;
                            const lat = document.getElementById('rule-latency-'+r.id);
                            const dot = document.getElementById('rule-status-dot-'+r.id);
                            if(lat && dot) {
                                if(r.status) { lat.innerHTML = '<span style="color:#10b981;font-weight:600">'+r.latency+' ms</span>'; dot.parentElement.className = 'badge success'; dot.parentElement.innerHTML = '<span class="status-dot pulse"></span> 运行中'; } 
                                else { lat.innerHTML = '<span style="color:#ef4444">离线</span>'; dot.parentElement.className = 'badge danger'; dot.parentElement.innerHTML = '<span class="status-dot"></span> 异常'; }
                            }
                            if(r.limit > 0) {
                                let pct = (r.total / r.limit) * 100; if(pct > 100) pct = 100;
                                const bar = document.getElementById('rule-bar-'+r.id);
                                if(bar) { bar.style.width = pct + '%'; bar.style.background = pct > 90 ? '#ef4444' : '#6366f1'; }
                                const txt = document.getElementById('rule-limit-text-'+r.id); if(txt) txt.innerText = pct.toFixed(1) + '%';
                            }
                        });
                    }

                    if(d.agents) d.agents.forEach(a => {
                        const loadContainer = document.getElementById('sys-status-'+a.name);
                        if(loadContainer) {
                            let cpu=0, mem=0, dsk=0;
                            let parts = a.sys_status.split('|');
                            parts.forEach(p => {
                                let kv = p.split(':');
                                if(kv.length === 2) {
                                    let val = parseFloat(kv[1]) || 0;
                                    if(kv[0]==='CPU') cpu = val;
                                    if(kv[0]==='MEM') mem = val;
                                    if(kv[0]==='DSK') dsk = val;
                                }
                            });
                            
                            const setBar = (type, val, dangerColor, safeColor) => {
                                const elVal = document.getElementById(type+'-val-'+a.name);
                                const elBar = document.getElementById(type+'-bar-'+a.name);
                                if(elVal && elBar) {
                                    elVal.innerText = val.toFixed(1)+'%';
                                    elBar.style.width = val+'%';
                                    elBar.style.background = val>80 ? dangerColor : safeColor;
                                }
                            };
                            
                            setBar('cpu', cpu, '#ef4444', '#10b981');
                            setBar('mem', mem, '#ef4444', '#3b82f6');
                            setBar('dsk', dsk, '#ef4444', '#fbbf24');
                        }
                    });

                    if(d.logs && document.getElementById('logs').classList.contains('active')) {
                        const tbody = document.getElementById('log-table-body');
                        let html = '';
                        d.logs.forEach(l => {
                            html += '<tr><td style="font-family:var(--font-mono);color:var(--text-sub)">'+l.time+'</td>' +
                                    '<td>'+l.ip+'</td>' +
                                    '<td><span class=\"badge\" style=\"background:var(--input-bg);color:var(--text-main);border:1px solid var(--border)\">'+l.action+'</span></td>' +
                                    '<td style=\"color:var(--text-sub)\">'+l.msg+'</td></tr>';
                        });
                        tbody.innerHTML = html;
                    }
                }
            } catch(err) { console.log(err); }
        };
        ws.onclose = () => setTimeout(connectWS, 3000);
    }
    connectWS();
</script>
<script>if ('serviceWorker' in navigator) { window.addEventListener('load', () => { navigator.serviceWorker.register('/sw.js'); }); }</script>
</body>
</html>`

const manifestJSON = `{
  "name": "GoRelay Pro",
  "short_name": "GoRelay",
  "description": "安全内网穿透控制台",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#09090b",
  "theme_color": "#6366f1",
  "icons": [
    {
      "src": "/icon.svg",
      "sizes": "192x192",
      "type": "image/svg+xml",
      "purpose": "any maskable"
    },
    {
      "src": "/icon.svg",
      "sizes": "512x512",
      "type": "image/svg+xml",
      "purpose": "any maskable"
    }
  ]
}`

const serviceWorkerJS = `
const CACHE_NAME = 'gorelay-pwa-v1';
self.addEventListener('install', event => {
    self.skipWaiting();
});
self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
`
