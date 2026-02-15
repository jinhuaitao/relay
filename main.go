package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"image/png"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
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
	_ "modernc.org/sqlite"
)

// --- 配置与常量 ---

const (
	AppVersion      = "v3.0.45" // 背景图形加深版
	DBFile          = "data.db"
	ConfigFile      = "config.json"
	WebPort         = ":8888"
	DownloadURL     = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
	GithubLatestAPI = "https://api.github.com/repos/jinhuaitao/relay/releases/latest" // GitHub API
	TCPKeepAlive    = 60 * time.Second
	UDPBufferSize   = 4 * 1024 * 1024
	CopyBufferSize  = 32 * 1024
	MaxLogEntries   = 200
	MaxLogRetention = 1000
)

// 支持多个 Agent 连接端口
var ControlPorts = []string{":9999", ":10086"}

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

	TotalTx   int64 `json:"total_tx"`
	TotalRx   int64 `json:"total_rx"`
	UserCount int64 `json:"user_count"`

	TargetStatus  bool  `json:"-"`
	TargetLatency int64 `json:"-"`
}

type OpLog struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Msg    string `json:"msg"`
}

type AppConfig struct {
	WebUser      string        `json:"web_user"`
	WebPass      string        `json:"web_pass"`
	AgentToken   string        `json:"agent_token"`
	AgentPorts   string        `json:"agent_ports"`
	MasterIP     string        `json:"master_ip"`
	MasterIPv6   string        `json:"master_ipv6"`
	MasterDomain string        `json:"master_domain"`
	IsSetup      bool          `json:"is_setup"`
	TgBotToken   string        `json:"tg_bot_token"`
	TgChatID     string        `json:"tg_chat_id"`
	TwoFAEnabled bool          `json:"two_fa_enabled"`
	TwoFASecret  string        `json:"two_fa_secret"`
	Rules        []LogicalRule `json:"saved_rules"`
	Logs         []OpLog       `json:"logs"`
}

type ForwardTask struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	Target     string `json:"target"`
	SpeedLimit int64  `json:"speed_limit"`
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
	activeTargets    sync.Map // 存储最新的目标地址
	agentTraffic     sync.Map
	agentUserCounts  sync.Map
	targetHealthMap  sync.Map
	sessions         = make(map[string]time.Time)
	configDirty      int32

	loginAttempts = sync.Map{}
	blockUntil    = sync.Map{}

	wsUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	wsClients  = make(map[*websocket.Conn]bool)
	wsMu       sync.Mutex

	isMasterTLS bool = false
	useTLS      bool = false
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
    total_rx INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    ip TEXT,
    action TEXT,
    msg TEXT
);`

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

	if _, err := os.Stat(ConfigFile); err == nil {
		var count int
		db.QueryRow("SELECT count(*) FROM settings").Scan(&count)
		if count == 0 {
			migrateOldData()
		}
	}
}

func migrateOldData() {
	log.Println("🚚 执行旧配置迁移...")
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return
	}
	var old AppConfig
	if err := json.Unmarshal(data, &old); err != nil {
		return
	}

	setDBSetting := func(k, v string) { _, _ = db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", k, v) }
	setDBSetting("web_user", old.WebUser)
	setDBSetting("web_pass", old.WebPass)
	setDBSetting("agent_token", old.AgentToken)
	setDBSetting("agent_ports", old.AgentPorts)
	setDBSetting("master_ip", old.MasterIP)
	setDBSetting("master_ipv6", old.MasterIPv6)
	setDBSetting("master_domain", old.MasterDomain)
	setDBSetting("is_setup", strconv.FormatBool(old.IsSetup))
	setDBSetting("tg_bot_token", old.TgBotToken)
	setDBSetting("tg_chat_id", old.TgChatID)
	setDBSetting("two_fa_enabled", strconv.FormatBool(old.TwoFAEnabled))
	setDBSetting("two_fa_secret", old.TwoFASecret)

	for _, r := range old.Rules {
		disabled := 0
		if r.Disabled {
			disabled = 1
		}
		_, _ = db.Exec(`INSERT INTO rules (id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx) 
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, "", r.Note, r.EntryAgent, r.EntryPort, r.ExitAgent, r.TargetIP, r.TargetPort, r.Protocol, r.BridgePort, r.TrafficLimit, disabled, r.SpeedLimit, r.TotalTx, r.TotalRx)
	}
	_ = os.Rename(ConfigFile, ConfigFile+".bak")
}

// --- 基础工具函数 ---

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

func autoGenerateCert() error {
	if _, err := os.Stat("server.crt"); err == nil {
		if _, err := os.Stat("server.key"); err == nil {
			return nil
		}
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GoRelay-Pro"},
			CommonName:   "GoRelay Master",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, _ := os.Create("server.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := os.OpenFile("server.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	return nil
}

// --- 通用更新逻辑 (Master/Agent 共享) ---

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
		// Windows
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Rename(oldPath, exePath) // 还原
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
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memStr := fmt.Sprintf("Mem: %dMB", m.Alloc/1024/1024)
	cpuStr := fmt.Sprintf("Go: %d", runtime.NumGoroutine())
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/loadavg"); err == nil {
			parts := strings.Fields(string(data))
			if len(parts) > 0 {
				cpuStr = "Load: " + parts[0]
			}
		}
	}
	return fmt.Sprintf("%s | %s", cpuStr, memStr)
}

func addLog(r *http.Request, action, msg string) {
	ip := "System"
	if r != nil {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			ip = f
		}
	}
	now := time.Now().Format("01-02 15:04:05")
	_, _ = db.Exec("INSERT INTO logs (time, ip, action, msg) VALUES (?,?,?,?)", now, ip, action, msg)
}

func addSystemLog(ip, action, msg string) {
	now := time.Now().Format("01-02 15:04:05")
	_, _ = db.Exec("INSERT INTO logs (time, ip, action, msg) VALUES (?,?,?,?)", now, ip, action, msg)
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

	svcName := "relay" // 默认为 Master 服务名
	if mode == "agent" {
		svcName = "gorelay" // Agent 服务名
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
		// 卸载
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

func sendTelegram(text string) {
	mu.Lock()
	token := config.TgBotToken
	chatID := config.TgChatID
	mu.Unlock()
	if token == "" || chatID == "" {
		return
	}
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	data := url.Values{}
	data.Set("chat_id", chatID)
	data.Set("text", text)
	go func() { http.PostForm(api, data) }()
}

// ================= MASTER =================

func runMaster() {
	autoGenerateCert()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			if atomic.CompareAndSwapInt32(&configDirty, 1, 0) {
				saveConfig()
			}
			cleanOldLogs()
			db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		}
	}()
	go broadcastLoop()
	go func() {
		var agentTlsConfig *tls.Config
		if _, err := os.Stat("server.crt"); err == nil {
			if _, err := os.Stat("server.key"); err == nil {
				if cert, err := tls.LoadX509KeyPair("server.crt", "server.key"); err == nil {
					agentTlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
					isMasterTLS = true
					log.Println("🔐 Master 已启用 TLS 模式")
				}
			}
		}
		if !isMasterTLS {
			log.Println("⚠️ Master 已启用 TCP 模式 (未找到证书或加载失败)")
		}

		portsStr := config.AgentPorts
		if portsStr == "" {
			portsStr = "9999"
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

				if isMasterTLS {
					ln, err = tls.Listen("tcp", p, agentTlsConfig)
				}
				if ln == nil {
					ln, err = net.Listen("tcp", p)
				}

				if err != nil {
					log.Printf("❌ 监听端口 %s 失败: %v", p, err)
					return
				}
				log.Printf("✅ Agent 监听端口启动: %s", p)

				for {
					c, err := ln.Accept()
					if err == nil {
						go handleAgentConn(c)
					}
				}
			}(pStr)
		}
	}()

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
	http.HandleFunc("/delete_agent", authMiddleware(handleDeleteAgent))
	http.HandleFunc("/update_settings", authMiddleware(handleUpdateSettings))
	http.HandleFunc("/download_config", authMiddleware(handleDownloadConfig))
	http.HandleFunc("/export_logs", authMiddleware(handleExportLogs))
	http.HandleFunc("/2fa/generate", authMiddleware(handle2FAGenerate))
	http.HandleFunc("/2fa/verify", authMiddleware(handle2FAVerify))
	http.HandleFunc("/2fa/disable", authMiddleware(handle2FADisable))
	http.HandleFunc("/restart", authMiddleware(handleRestart))          // 新增重启路由
	http.HandleFunc("/update_sys", authMiddleware(handleUpdateSystem))  // 系统更新路由
	http.HandleFunc("/update_agent", authMiddleware(handleUpdateAgent)) // Agent更新路由
	http.HandleFunc("/check_update", authMiddleware(handleCheckUpdate)) // [新增] 检查更新路由

	log.Printf("面板启动: http://localhost%s", WebPort)
	log.Fatal(http.ListenAndServe(WebPort, nil))
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

		for _, a := range agents {
			agentData = append(agentData, AgentStatusData{Name: a.Name, SysStatus: a.SysStatus})
		}
		for _, r := range rules {
			currentTx += r.TotalTx
			currentRx += r.TotalRx
			ruleData = append(ruleData, RuleStatusData{
				ID:        r.ID,
				Name:      r.Note,
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
		lRows, err := db.Query("SELECT time, ip, action, msg FROM logs ORDER BY id DESC LIMIT 15")
		if err == nil {
			for lRows.Next() {
				var l OpLog
				lRows.Scan(&l.Time, &l.IP, &l.Action, &l.Msg)
				logData = append(logData, l)
			}
			lRows.Close()
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
	tk := config.AgentToken
	mu.Unlock()
	if reqToken != tk || name == "" {
		return
	}

	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	mu.Lock()
	if old, exists := agents[name]; exists {
		old.Conn.Close()
	}
	agents[name] = &AgentInfo{Name: name, RemoteIP: remoteIP, Conn: conn}
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

					if rules[i].TrafficLimit > 0 && (rules[i].TotalTx+rules[i].TotalRx) >= rules[i].TrafficLimit {
						limitTriggered = true
					}
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
		tasksMap[r.ExitAgent] = append(tasksMap[r.ExitAgent], ForwardTask{
			ID: r.ID + "_exit", Protocol: r.Protocol, Listen: ":" + r.BridgePort, Target: finalTargetStr, SpeedLimit: r.SpeedLimit,
		})
		if exit, ok := agents[r.ExitAgent]; ok {
			rip := exit.RemoteIP
			if strings.Contains(rip, ":") && !strings.Contains(rip, "[") {
				rip = "[" + rip + "]"
			}
			tasksMap[r.EntryAgent] = append(tasksMap[r.EntryAgent], ForwardTask{
				ID: r.ID + "_entry", Protocol: r.Protocol, Listen: ":" + r.EntryPort, Target: fmt.Sprintf("%s:%s", rip, r.BridgePort), SpeedLimit: r.SpeedLimit,
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

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	al := make([]AgentInfo, 0)
	for _, a := range agents {
		al = append(al, *a)
	}
	var totalTraffic int64
	for _, r := range rules {
		totalTraffic += (r.TotalTx + r.TotalRx)
	}
	displayRules := make([]LogicalRule, len(rules))
	copy(displayRules, rules)
	mu.Unlock()

	// 排序规则
	sort.Slice(displayRules, func(i, j int) bool {
		if displayRules[i].Group == displayRules[j].Group {
			return displayRules[i].ID < displayRules[j].ID
		}
		return displayRules[i].Group < displayRules[j].Group
	})

	var displayLogs []OpLog
	rows, err := db.Query("SELECT time, ip, action, msg FROM logs ORDER BY id DESC LIMIT ?", MaxLogEntries)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var l OpLog
			rows.Scan(&l.Time, &l.IP, &l.Action, &l.Msg)
			displayLogs = append(displayLogs, l)
		}
	}

	mu.Lock()
	conf := config
	mu.Unlock()

	// 准备端口列表给前端 (从配置中读取)
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
		Agents       []AgentInfo
		Rules        []LogicalRule
		Logs         []OpLog
		Token        string
		User         string
		DownloadURL  string
		TotalTraffic int64
		MasterIP     string
		MasterIPv6   string
		MasterDomain string
		Config       AppConfig
		TwoFA        bool
		IsTLS        bool
		Ports        []string // 新增: 传递端口列表
		Version      string
	}{al, displayRules, displayLogs, conf.AgentToken, conf.WebUser, DownloadURL, totalTraffic, conf.MasterIP, conf.MasterIPv6, conf.MasterDomain, conf, conf.TwoFAEnabled, isMasterTLS, cleanPorts, AppVersion}

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
	if r.Method == "POST" {
		mu.Lock()
		config.WebUser = r.FormValue("username")
		salt := generateSalt()
		pwdHash := hashPassword(r.FormValue("password"), salt)
		config.WebPass = salt + "$" + pwdHash
		config.AgentToken = r.FormValue("token")
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
		mu.Unlock()
		t, _ := template.New("l").Parse(loginHtml)
		t.Execute(w, map[string]interface{}{"TwoFA": isEnabled})
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
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
	sessions[sidStr] = time.Now().Add(12 * time.Hour)
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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

	// [还原] 移除手动指定 bridge_port，恢复随机生成
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
			rules[i].TrafficLimit = int64(limitGB * 1024 * 1024 * 1024)
			rules[i].SpeedLimit = int64(speedMB * 1024 * 1024)
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
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
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
	mu.Lock()
	if p := r.FormValue("password"); p != "" {
		salt := generateSalt()
		config.WebPass = salt + "$" + hashPassword(p, salt)
	}
	config.AgentToken = r.FormValue("token")
	config.AgentPorts = r.FormValue("agent_ports") // 保存新添加的端口配置
	config.MasterIP = r.FormValue("master_ip")
	config.MasterIPv6 = r.FormValue("master_ipv6")
	config.MasterDomain = r.FormValue("master_domain")
	config.TgBotToken = r.FormValue("tg_bot_token")
	config.TgChatID = r.FormValue("tg_chat_id")
	saveConfigNoLock()
	mu.Unlock()
	http.Redirect(w, r, "/#settings", http.StatusSeeOther)
}

func handleDownloadConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=data.db")
	http.ServeFile(w, r, DBFile)
}

func handleExportLogs(w http.ResponseWriter, r *http.Request) {
	var logs []OpLog
	rows, err := db.Query("SELECT time, ip, action, msg FROM logs ORDER BY id DESC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var l OpLog
			rows.Scan(&l.Time, &l.IP, &l.Action, &l.Msg)
			logs = append(logs, l)
		}
	}
	b, _ := json.MarshalIndent(logs, "", "  ")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
	w.Write(b)
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

// Master自我更新处理
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

// Master远程通知Agent更新
func handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	agent, ok := agents[name]
	mu.Unlock()
	if !ok {
		http.Error(w, "Agent not found", 404)
		return
	}
	// 发送更新指令给Agent
	json.NewEncoder(agent.Conn).Encode(Message{Type: "upgrade"})
	w.Write([]byte("ok"))
}

// [新增] 检查更新接口
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

	// 简单对比版本号
	remoteVer := strings.TrimPrefix(data.TagName, "v")
	currentVer := strings.TrimPrefix(AppVersion, "v")

	hasUpdate := remoteVer != currentVer // 简单对比：只要字符串不同就提示更新 (简化逻辑)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"has_update":     hasUpdate,
		"latest_version": data.TagName,
		"current":        AppVersion,
	})
}

func doRestart() {
	log.Println("🔄 接收到重启指令...")

	// [修改] 自动检测存在的服务名进行重启 (relay 或 gorelay)
	services := []string{"relay", "gorelay"}

	// 1. 尝试 Systemd
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

	// 2. 尝试 OpenRC
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

	// 3. 直接二进制重启 (Standalone/Docker/Manual)
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
			conn, err = tls.Dial("tcp", masterAddr, &tls.Config{InsecureSkipVerify: true})
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
					} else {
						json.NewEncoder(conn).Encode(Message{Type: "ping", Payload: getSysStatus()})
					}
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
			// --- Agent 接收更新指令 ---
			if msg.Type == "upgrade" {
				log.Println("收到更新指令，开始执行自我更新...")
				if err := performSelfUpdate(); err == nil {
					doRestart()
				} else {
					log.Printf("更新失败: %v", err)
				}
			}
			// ------------------------
			if msg.Type == "update" {
				d, _ := json.Marshal(msg.Payload)
				var tasks []ForwardTask
				json.Unmarshal(d, &tasks)
				active := make(map[string]bool)
				for _, t := range tasks {
					active[t.ID] = true

					// [保留] IP 变动热更新：强制更新内存中的目标地址
					activeTargets.Store(t.ID, t.Target)

					if _, loaded := activeTasks.LoadOrStore(t.ID, t); !loaded {
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
					}
					return true
				})
			}
		}
		time.Sleep(3 * time.Second)
	}
}

// doPing 使用系统 Ping 命令检测目标主机存活 (耗时作为延迟参考)
func doPing(address string) (int64, bool) {
	// 去掉端口号，Ping 只需要 IP 或域名
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// 如果没有端口号（本身就是纯 IP），直接用
		if strings.Contains(err.Error(), "missing port") {
			host = address
		} else {
			return -1, false
		}
	}

	var cmd *exec.Cmd
	// 根据系统不同构建命令
	if runtime.GOOS == "windows" {
		// Windows: -n 1 (次数), -w 1000 (超时ms)
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", host)
	} else {
		// Linux/Mac: -c 1 (次数), -W 1 (超时s)
		cmd = exec.Command("ping", "-c", "1", "-W", "1", host)
	}

	// 记录开始时间
	start := time.Now()
	// 执行命令 (如果目标不可达，Run() 会返回 error)
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
		// 1. 获取检测模式
		checkMode := "tcp"
		if tVal, ok := activeTasks.Load(key); ok {
			if t, ok := tVal.(ForwardTask); ok {
				if t.Protocol == "udp" {
					checkMode = "ping" // 纯 UDP -> 只测 Ping
				} else if t.Protocol == "both" {
					checkMode = "mixed" // TCP+UDP -> 混合双打
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

			// 2. 根据模式执行检测
			if checkMode == "ping" {
				// --- 模式 A: 只测 Ping (适用于纯 UDP) ---
				lat, success = doPing(target)

			} else if checkMode == "mixed" {
				// --- 模式 B: 混合检测 (适用于 Both) ---
				// 第一步：先尝试 TCP (最准)
				start := time.Now()
				c, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err == nil {
					c.Close()
					lat = time.Since(start).Milliseconds()
					success = true
				} else {
					// 第二步：TCP 失败了？别急，可能是纯 UDP 节点，试一下 Ping
					lat, success = doPing(target)
				}

			} else {
				// --- 模式 C: 只测 TCP (适用于纯 TCP) ---
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

			// 3. 记录结果
			if success {
				if bestLat == -1 || lat < bestLat {
					bestLat = lat
				}
				targetHealthMap.Store(target, true)
			} else {
				targetHealthMap.Store(target, false)
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

	// 关键修复：检查该 Host 是否确实存在于 map 中
	if count, exists := t.refs[host]; !exists || count <= 0 {
		return // 如果已经不存在或计数为0，直接忽略，避免重复扣减
	}

	t.refs[host]--
	
	if t.refs[host] <= 0 {
		delete(t.refs, host)
		// 防御性编程：确保不会减成负数
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
					// [保留] IP 动态获取，修复旧 IP 问题
					pipeTCP(conn, t.ID, t.SpeedLimit)
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
			// [保留] IP 动态获取
			handleUDP(ln, t.ID, ipTracker, t.SpeedLimit)
		}()
	}
}

// [保留] IP 热更新逻辑
func pipeTCP(src net.Conn, tid string, limit int64) {
	defer src.Close()

	// [保留] 每次连接时，从 activeTargets 获取最新的 Target IP
	var targetStr string
	if v, ok := activeTargets.Load(tid); ok {
		targetStr = v.(string)
	} else {
		return // 任务可能已被删除
	}

	allTargets := strings.Split(targetStr, ",")
	var candidates []string
	for _, t := range allTargets {
		t = strings.TrimSpace(t)
		if status, ok := targetHealthMap.Load(t); ok && status.(bool) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		candidates = allTargets
	}
	randIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	dst, err := net.DialTimeout("tcp", strings.TrimSpace(candidates[randIdx.Int64()]), 2*time.Second)
	if err != nil {
		return
	}
	defer dst.Close()
	v, _ := agentTraffic.Load(tid)
	cnt := v.(*TrafficCounter)
	go copyCount(dst, src, &cnt.Tx, limit)
	copyCount(src, dst, &cnt.Rx, limit)
}

// [保留] IP 热更新逻辑
func handleUDP(ln *net.UDPConn, tid string, tracker *IpTracker, limit int64) {
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
			// [保留] 每次建立新 UDP Session 时，获取最新的 Target IP
			var currentTargetStr string
			if v, ok := activeTargets.Load(tid); ok {
				currentTargetStr = v.(string)
			} else {
				continue
			}
			targets := strings.Split(currentTargetStr, ",")

			randIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(targets))))
			dstAddr, _ := net.ResolveUDPAddr("udp", strings.TrimSpace(targets[randIdx.Int64()]))
			newConn, err := net.DialUDP("udp", nil, dstAddr)
			if err != nil {
				continue
			}
			s := &udpSession{conn: newConn, lastActive: time.Now()}
			udpSessions.Store(sAddr, s)
			tracker.Add(sAddr)
			newConn.Write(buf[:n])
			go func(c *net.UDPConn, sa *net.UDPAddr, k string) {
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
						break
					}
					ln.WriteToUDP(b[:m], sa)
					atomic.AddInt64(&cnt.Rx, int64(m))
				}
			}(newConn, srcAddr, sAddr)
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
			case "agent_ports":
				config.AgentPorts = v
			case "master_ip":
				config.MasterIP = v
			case "master_ipv6":
				config.MasterIPv6 = v
			case "master_domain":
				config.MasterDomain = v
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
			}
		}
	}

	rules = []LogicalRule{}
	rRows, err := db.Query("SELECT id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx FROM rules")
	if err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var r LogicalRule
			var d int
			rRows.Scan(&r.ID, &r.Group, &r.Note, &r.EntryAgent, &r.EntryPort, &r.ExitAgent, &r.TargetIP, &r.TargetPort, &r.Protocol, &r.BridgePort, &r.TrafficLimit, &d, &r.SpeedLimit, &r.TotalTx, &r.TotalRx)
			r.Disabled = (d == 1)
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
	setS("agent_ports", conf.AgentPorts)
	setS("master_ip", conf.MasterIP)
	setS("master_ipv6", conf.MasterIPv6)
	setS("master_domain", conf.MasterDomain)
	setS("is_setup", strconv.FormatBool(conf.IsSetup))
	setS("tg_bot_token", conf.TgBotToken)
	setS("tg_chat_id", conf.TgChatID)
	setS("two_fa_enabled", strconv.FormatBool(conf.TwoFAEnabled))
	setS("two_fa_secret", conf.TwoFASecret)

	_, _ = tx.Exec("DELETE FROM rules")
	for _, r := range lRules {
		d := 0
		if r.Disabled {
			d = 1
		}
		_, _ = tx.Exec(`INSERT INTO rules (id, group_name, note, entry_agent, entry_port, exit_agent, target_ip, target_port, protocol, bridge_port, traffic_limit, disabled, speed_limit, total_tx, total_rx) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Group, r.Note, r.EntryAgent, r.EntryPort, r.ExitAgent, r.TargetIP, r.TargetPort, r.Protocol, r.BridgePort, r.TrafficLimit, d, r.SpeedLimit, r.TotalTx, r.TotalRx)
	}
	_ = tx.Commit()
}

func cleanOldLogs() {
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
    <p>欢迎使用，请配置初始管理员账户<br>并设置通信 Token 密钥</p>
    <div class="input-group"><input name="username" placeholder="管理员用户名" required autocomplete="off"><i class="ri-user-line"></i></div>
    <div class="input-group"><input type="password" name="password" placeholder="登录密码" required><i class="ri-lock-password-line"></i></div>
    <div class="input-group"><input name="token" placeholder="通信 Token (Agent 连接密钥)" required><i class="ri-key-2-line"></i></div>
    <button>完成初始化 <i class="ri-arrow-right-line"></i></button>
</form>
</body>
</html>`

const loginHtml = `<!DOCTYPE html>
<html lang="zh" data-theme="dark">
<head>
<title>登录 - GoRelay Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root { --primary: #6366f1; --bg: #09090b; --card-bg: #18181b; --text: #fafafa; --text-sub: #a1a1aa; --border: #27272a; --input-bg: #27272a; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; position: relative; }
.bg-glow { position: absolute; width: 600px; height: 600px; background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%); top: -20%; left: 50%; transform: translateX(-50%); opacity: 0.6; pointer-events: none; }

.card { background: rgba(24, 24, 27, 0.6); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 48px 40px; border-radius: 24px; width: 100%; max-width: 340px; border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.5); position: relative; z-index: 10; }
.header { text-align: center; margin-bottom: 36px; }
.logo-icon { width: 56px; height: 56px; background: linear-gradient(135deg, #6366f1, #a855f7); border-radius: 16px; display: inline-flex; align-items: center; justify-content: center; font-size: 32px; color: white; box-shadow: 0 10px 20px -5px rgba(99,102,241,0.4); margin-bottom: 20px; }
.header h2 { margin: 0; font-size: 20px; font-weight: 600; color: var(--text); letter-spacing: -0.5px; }
.header p { margin: 6px 0 0; color: var(--text-sub); font-size: 13px; }

.input-box { margin-bottom: 16px; position: relative; }
.input-box i { position: absolute; left: 14px; top: 13px; color: var(--text-sub); font-size: 18px; transition: .2s; }
input { width: 100%; padding: 12px 14px 12px 44px; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border); border-radius: 12px; color: var(--text); font-size: 14px; outline: none; transition: .2s; box-sizing: border-box; }
input:focus { border-color: var(--primary); background: rgba(0,0,0,0.4); box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); }
input:focus + i { color: var(--primary); }

button { width: 100%; padding: 12px; background: var(--primary); color: #fff; border: none; border-radius: 12px; font-size: 14px; font-weight: 500; cursor: pointer; transition: .2s; margin-top: 12px; display: flex; align-items: center; justify-content: center; gap: 8px; }
button:hover { background: #4f46e5; transform: translateY(-1px); }
.error-msg { background: rgba(239, 68, 68, 0.1); color: #ef4444; padding: 10px; border-radius: 8px; font-size: 12px; margin-bottom: 20px; text-align: center; border: 1px solid rgba(239, 68, 68, 0.2); display: flex; align-items: center; justify-content: center; gap: 6px; }
</style>
</head>
<body>
<div class="bg-glow"></div>
<form class="card" method="POST">
    <div class="header">
        <div class="logo-icon"><i class="ri-globe-line"></i></div>
        <h2>GoRelay Pro</h2>
        <p>安全内网穿透控制台</p>
    </div>
    {{if .Error}}<div class="error-msg"><i class="ri-error-warning-fill"></i> {{.Error}}</div>{{end}}
    
    <div class="input-box"><input name="username" placeholder="管理员账号" required autocomplete="off"><i class="ri-user-3-line"></i></div>
    <div class="input-box"><input type="password" name="password" placeholder="登录密码" required><i class="ri-lock-2-line"></i></div>
    {{if .TwoFA}}
    <div class="input-box"><input name="code" placeholder="2FA 动态验证码" required pattern="[0-9]{6}" maxlength="6" style="letter-spacing: 4px; text-align: center; padding-left: 14px; font-weight: 600; font-family: monospace"><i class="ri-shield-keyhole-line" style="left: auto; right: 14px;"></i></div>
    {{end}}
    <button>立即登录 <i class="ri-arrow-right-line"></i></button>
</form>
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

/* 增强背景装饰层 (圆形、星星图案) - 高对比度调整 */
.bg-decor { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; pointer-events: none; overflow: hidden; }
.shape { position: absolute; opacity: 0.15; } /* 基础不透明度提升至 0.15 */
[data-theme="dark"] .shape { opacity: 0.12; } /* 深色模式下不透明度提升至 0.12 */

.shape-circle { border-radius: 50%; background: var(--primary); }
.shape-star { background: var(--text-sub); clip-path: polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%); }

/* 具体的图形定位与动画 - 增加可见度 */
.s1 { top: 10%; left: 5%; width: 300px; height: 300px; background: linear-gradient(45deg, var(--primary), var(--success)); filter: blur(60px); opacity: 0.2; } /* 渐变色块增强 */
.s2 { bottom: 15%; right: -5%; width: 400px; height: 400px; background: linear-gradient(to top, var(--primary), #8b5cf6); filter: blur(80px); opacity: 0.2; }

.shape-c1 { top: 15%; right: 15%; width: 80px; height: 80px; border: 4px solid var(--primary); background: transparent; opacity: 0.25; animation: float 10s ease-in-out infinite; } /* 圆环增强 */
.shape-st1 { bottom: 10%; left: 8%; width: 120px; height: 120px; opacity: 0.15; background: var(--text-main); transform: rotate(-15deg); animation: float 12s ease-in-out infinite reverse; }
.shape-c2 { bottom: 30%; right: 25%; width: 40px; height: 40px; background: var(--warning); opacity: 0.2; animation: float 8s ease-in-out infinite 1s; }
.shape-st2 { top: 20%; left: 20%; width: 30px; height: 30px; background: var(--success); opacity: 0.25; animation: float 14s ease-in-out infinite 2s; }

/* 新增的更多图形 - 同样增强可见度 */
.shape-c3 { top: 40%; left: 15%; width: 60px; height: 60px; border: 2px dashed var(--text-sub); background: transparent; opacity: 0.15; animation: rotate 30s linear infinite; }
.shape-st3 { top: 5%; left: 50%; width: 25px; height: 25px; background: var(--danger); opacity: 0.2; animation: float 18s ease-in-out infinite 3s; }
.shape-c4 { bottom: 20%; left: 40%; width: 20px; height: 20px; background: var(--primary); opacity: 0.2; animation: float 10s infinite; }
.shape-st4 { top: 60%; right: 10%; width: 50px; height: 50px; background: var(--success); opacity: 0.15; animation: float 22s infinite reverse; }
.shape-c5 { top: 80%; left: 5%; width: 100px; height: 100px; border: 6px solid var(--danger); background: transparent; opacity: 0.1; animation: float 25s infinite; }
.shape-st5 { top: 8%; right: 30%; width: 35px; height: 35px; background: var(--text-main); opacity: 0.15; animation: float 13s infinite; }
.shape-c6 { bottom: 5%; left: 60%; width: 150px; height: 150px; border: 1px solid var(--text-sub); background: transparent; opacity: 0.1; animation: rotate 45s linear infinite reverse; }
.shape-st6 { bottom: 40%; right: 40%; width: 15px; height: 15px; background: var(--warning); opacity: 0.3; animation: float 9s infinite; }
.shape-c7 { top: 30%; left: 35%; width: 10px; height: 10px; background: var(--success); opacity: 0.3; animation: float 7s infinite; }

@keyframes float { 0% { transform: translateY(0px) rotate(0deg); } 50% { transform: translateY(-15px) rotate(5deg); } 100% { transform: translateY(0px) rotate(0deg); } }
@keyframes rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

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

/* 核心布局修复：移动端强制单列堆叠，确保图表卡片全宽 */
.dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 24px; }
.chart-box { height: 320px; width: 100%; position: relative; }
@media (max-width: 1024px) { 
    .dashboard-grid { grid-template-columns: 100%; } /* 强制单列 */
}

/* 关键修复：表格容器最小宽度，确保移动端不重叠，启用横向滚动 */
.table-container { overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); background: var(--bg-card); }
.table-container table { min-width: 600px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; }
th { text-align: left; padding: 14px 20px; color: var(--text-sub); font-size: 12px; font-weight: 600; background: var(--input-bg); border-bottom: 1px solid var(--border); }
td { padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--text-main); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--input-bg); }

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
}

.toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(20px); background: #0f172a; color: #fff; padding: 10px 20px; border-radius: 50px; font-size: 13px; opacity: 0; visibility: hidden; transition: 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index: 2000; display: flex; align-items: center; gap: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); }
.toast.show { opacity: 1; visibility: visible; transform: translateX(-50%) translateY(0); bottom: 80px; }
</style>
</head>
<body>

<div class="bg-decor">
    <div class="shape shape-circle s1"></div>
    <div class="shape shape-circle s2"></div>
    <div class="shape shape-circle shape-c1"></div>
    <div class="shape shape-star shape-st1"></div>
    <div class="shape shape-circle shape-c2"></div>
    <div class="shape shape-star shape-st2"></div>
    
    <div class="shape shape-circle shape-c3"></div>
    <div class="shape shape-star shape-st3"></div>
    <div class="shape shape-circle shape-c4"></div>
    <div class="shape shape-star shape-st4"></div>
    <div class="shape shape-circle shape-c5"></div>
    <div class="shape shape-star shape-st5"></div>
    <div class="shape shape-circle shape-c6"></div>
    <div class="shape shape-star shape-st6"></div>
    <div class="shape shape-circle shape-c7"></div>
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
                        <tbody id="rule-monitor-body"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="rules" class="page">
            <div class="card">
                <h3><i class="ri-add-circle-line" style="color:var(--primary)"></i> 新建转发规则</h3>
                <form action="/add" method="POST">
                    <div class="grid-form">
                        <div class="form-group"><label>分组名称</label><input name="group" placeholder="例如: 业务A (留空为默认)"></div>
                        <div class="form-group"><label>备注名称</label><input name="note" placeholder="例如: 远程桌面" required></div>
                        <div class="form-group"><label>入口节点</label><select name="entry_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                        <div class="form-group"><label>入口端口</label><input type="number" name="entry_port" placeholder="1024-65535" required></div>
                        <div class="form-group"><label>出口节点</label><select name="exit_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                        <div class="form-group"><label>目标 IP (支持多IP/域名)</label><input name="target_ip" placeholder="192.168.1.1, 10.0.0.1,[ IPV6 ]" required></div>
                        <div class="form-group"><label>目标端口</label><input type="number" name="target_port" required></div>

                        <div class="form-group"><label>流量限制 (GB)</label><input type="number" step="0.1" name="traffic_limit" placeholder="0 为不限"></div>
                        <div class="form-group"><label>带宽限速 (MB/s)</label><input type="number" step="0.1" name="speed_limit" placeholder="0 为不限"></div>
                        <div class="form-group"><label>协议类型</label><select name="protocol"><option value="tcp">TCP (推荐)</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></div>
                        <div class="form-group"><button class="btn" style="width:100%"><i class="ri-save-line"></i> 保存并生效</button></div>
                    </div>
                </form>
            </div>

            <div class="card">
                <h3><i class="ri-list-settings-line"></i> 规则列表</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>链路信息</th><th>目标地址 & 延迟</th><th>流量监控</th><th>状态</th><th>操作</th></tr></thead>
                        <tbody>
                        {{$currentGroup := "INIT_h7&^"}}
                        {{range .Rules}}
                        {{if ne .Group $currentGroup}}
                            <tr class="group-header" onclick="toggleGroup(this)" data-group="{{.Group}}">
                                <td colspan="5">
                                    <i class="ri-arrow-down-s-line group-icon"></i>
                                    <i class="ri-folder-3-fill" style="margin-right:4px"></i> 
                                    {{if .Group}}{{.Group}}{{else}}默认分组{{end}}
                                </td>
                            </tr>
                            {{$currentGroup = .Group}}
                        {{end}}
                        <tr class="rule-row" data-group="{{.Group}}" style="{{if .Disabled}}opacity:0.6;filter:grayscale(1);{{end}}">
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
                                    <button class="btn icon secondary" onclick="openEdit('{{.ID}}','{{.Group}}','{{.Note}}','{{.EntryAgent}}','{{.EntryPort}}','{{.ExitAgent}}','{{.TargetIP}}','{{.TargetPort}}','{{.Protocol}}','{{.TrafficLimit}}','{{.SpeedLimit}}')" title="编辑"><i class="ri-edit-line"></i></button>
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
                    请在您的 VPS 或服务器（支持 Linux）上执行以下命令以安装 Agent 客户端。Agent 安装后将自动连接至本面板。
                </p>
                
                <div style="background:var(--input-bg);padding:24px;border-radius:16px;border:1px solid var(--border)">
                    <div class="grid-form" style="margin-bottom:24px;grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                        <div class="form-group"><label>1. 节点名称</label><input id="agentName" value="Node-01"></div>
                        <div class="form-group"><label>2. 连接方式</label><select id="addrType"><option value="domain">域名 ({{.MasterDomain}})</option><option value="v4">IPv4 ({{.MasterIP}})</option><option value="v6">IPv6 ({{.MasterIPv6}})</option></select></div>
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
                            <span style="color:#64748b;font-size:12px;margin-left:auto">bash</span>
                        </div>
                        <div class="terminal-body">
                            <div class="copy-overlay"><button class="btn icon secondary" style="background:rgba(255,255,255,0.1);color:#fff;border:none" onclick="copyCmd()" title="复制"><i class="ri-file-copy-line"></i></button></div>
                            <span style="color:#10b981">root@server:~$</span> <span id="cmdText" style="opacity:0.8">请先点击上方按钮生成命令...</span><span style="animation:blink 1s infinite"></span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3><i class="ri-server-line"></i> 在线节点状态</h3>
                <div class="table-container">
                    {{if .Agents}}
                    <table>
                        <thead><tr><th>状态</th><th>节点名称</th><th>远程 IP</th><th>系统负载 (Load)</th><th>操作</th></tr></thead>
                        <tbody>
                        {{range .Agents}}
                        <tr>
                            <td><span class="badge success"><span class="status-dot pulse"></span> 在线</span></td>
                            <td><div style="font-weight:600">{{.Name}}</div></td>
                            <td><span class="badge" style="font-family:var(--font-mono);background:var(--input-bg);color:var(--text-sub);cursor:pointer" onclick="copyText('{{.RemoteIP}}')">{{.RemoteIP}}</span></td>
                            <td style="width:240px">
                                <div style="display:flex;align-items:center;gap:12px">
                                    <div class="progress" style="margin:0;flex:1"><div class="progress-bar" id="load-bar-{{.Name}}" style="width:0%"></div></div>
                                    <span id="load-text-{{.Name}}" style="font-size:12px;font-family:var(--font-mono);min-width:50px;text-align:right">0.0</span>
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
                    <a href="/export_logs" class="btn secondary" style="text-decoration:none;font-size:13px"><i class="ri-download-line"></i> 导出</a>
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
            <div class="card" style="max-width:800px">
                <h3><i class="ri-settings-line"></i> 系统全局配置</h3>
                <form action="/update_settings" method="POST">
                    <div class="grid-form" style="grid-template-columns: 1fr; gap:24px">
                        
                        <div style="display:grid;grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));gap:20px">
                            <div class="form-group"><label>修改密码</label><input type="password" name="password" placeholder="留空则不修改"></div>
                            <div class="form-group"><label>通信 Token</label><input name="token" value="{{.Token}}"></div>
                        </div>

                        <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px dashed var(--border);grid-column:1/-1">
                            <h4 style="margin:0 0 10px 0;font-size:14px;"><i class="ri-plug-line"></i> Agent 监听端口</h4>
                            <div class="form-group" style="margin:0">
                                <label style="font-weight:400;font-size:12px">Master 监听的端口 (逗号分隔，例如: 9999,10086)</label>
                                <input name="agent_ports" value="{{if .Config.AgentPorts}}{{.Config.AgentPorts}}{{else}}9999{{end}}" placeholder="9999">
                                <div style="font-size:12px;color:var(--warning-text);margin-top:6px;"><i class="ri-alert-line"></i> 修改后需手动重启服务</div>
                            </div>
                        </div>
                        
                        <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);grid-column:1/-1">
                            <h4 style="margin:0 0 16px 0;font-size:14px;color:#3b82f6"><i class="ri-telegram-fill"></i> Telegram 通知</h4>
                            <div class="grid-form" style="gap:16px;grid-template-columns: 1fr 1fr;">
                                <div class="form-group"><label>Bot Token</label><input name="tg_bot_token" value="{{.Config.TgBotToken}}"></div>
                                <div class="form-group"><label>Chat ID</label><input name="tg_chat_id" value="{{.Config.TgChatID}}"></div>
                            </div>
                        </div>

                        <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;grid-column:1/-1">
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

                        <div style="background:rgba(16,185,129,0.05);padding:20px;border-radius:12px;border:1px solid rgba(16,185,129,0.2);grid-column:1/-1;display:flex;justify-content:space-between;align-items:center">
                            <div>
                                <h4 style="margin:0 0 4px 0;font-size:14px;color:#10b981">系统更新</h4>
                                <div style="font-size:12px;color:var(--text-sub)">当前: {{.Version}} <span id="new-version-text" style="color:#f59e0b;display:none;margin-left:8px;font-weight:600">发现新版本</span></div>
                            </div>
                            <div>
                                <button type="button" class="btn success" onclick="updateSystem()" id="btn-update">检查更新</button>
                            </div>
                        </div>

                        <div class="grid-form" style="gap:16px;margin-top:10px;grid-column:1/-1;grid-template-columns: 1fr 1fr 1fr;">
                            <div class="form-group"><label>面板域名</label><input name="master_domain" value="{{.MasterDomain}}"></div>
                            <div class="form-group"><label>IPv4</label><input name="master_ip" value="{{.MasterIP}}"></div>
                            <div class="form-group"><label>IPv6</label><input name="master_ipv6" value="{{.MasterIPv6}}"></div>
                        </div>

                        <div style="display:flex;gap:12px;margin-top:16px;border-top:1px solid var(--border);padding-top:24px;grid-column:1/-1">
                            <button class="btn" style="flex:2;height:44px">保存配置</button>
                            <a href="/download_config" class="btn secondary" style="flex:1;height:44px" title="备份数据库"><i class="ri-database-2-line"></i></a>
                            <button type="button" class="btn warning" style="flex:1;height:44px" onclick="restartService()" title="重启服务"><i class="ri-restart-line"></i></button>
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

<div id="editModal" class="modal">
    <div class="modal-content">
        <span class="close-modal" onclick="closeEdit()"><i class="ri-close-line"></i></span>
        <h3 style="margin-top:0;font-size:18px">修改规则</h3>
        <form action="/edit" method="POST">
            <input type="hidden" name="id" id="e_id">
            <div class="grid-form" style="grid-template-columns: 1fr 1fr; gap:20px">
                <div class="form-group"><label>分组</label><input name="group" id="e_group" placeholder="例如: 业务A"></div>
                <div class="form-group"><label>备注</label><input name="note" id="e_note"></div>
                <div class="form-group"><label>入口节点</label><select name="entry_agent" id="e_entry">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group"><label>入口端口</label><input type="number" name="entry_port" id="e_eport"></div>
                <div class="form-group"><label>出口节点</label><select name="exit_agent" id="e_exit">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group" style="grid-column: 1/-1"><label>目标地址 (IP/域名)</label><input name="target_ip" id="e_tip"></div>
                <div class="form-group"><label>目标端口</label><input type="number" name="target_port" id="e_tport"></div>
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
    var m_domain="{{.MasterDomain}}", m_v4="{{.MasterIP}}", m_v6="{{.MasterIPv6}}", token="{{.Token}}", dwUrl="{{.DownloadURL}}", is_tls={{.IsTLS}};
    var lastRuleStats = {}; 
    var ruleCharts = {}; 
    
    function createMiniChartConfig(color) {
        const ctxGrad = document.createElement('canvas').getContext('2d').createLinearGradient(0, 0, 0, 32);
        ctxGrad.addColorStop(0, color.replace(')', ', 0.3)').replace('rgb', 'rgba'));
        ctxGrad.addColorStop(1, color.replace(')', ', 0)').replace('rgb', 'rgba'));

        return {
            type: 'line',
            data: {
                labels: Array(15).fill(''),
                datasets: [{
                    data: Array(15).fill(0),
                    borderColor: color,
                    backgroundColor: ctxGrad,
                    borderWidth: 1.5,
                    pointRadius: 0,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: {display: false}, tooltip: {enabled: false} },
                scales: { x: {display: false}, y: {display: false, min: 0} },
                elements: { line: { borderJoinStyle: 'round' } }
            }
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

    document.addEventListener('DOMContentLoaded', () => {
        const collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        collapsed.forEach(g => {
            const header = document.querySelector('.group-header[data-group="'+g+'"]');
            if(header) setGroupState(header, false); 
        });
        checkUpdate();
    });

    function toggleGroup(header) {
        const isCurrentlyCollapsed = header.classList.contains('group-collapsed');
        setGroupState(header, isCurrentlyCollapsed); 
        const group = header.getAttribute('data-group');
        let collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        if (isCurrentlyCollapsed) { collapsed = collapsed.filter(i => i !== group); } else { if(!collapsed.includes(group)) collapsed.push(group); }
        localStorage.setItem('collapsed_groups', JSON.stringify(collapsed));
    }

    function setGroupState(header, expand) {
        const group = header.getAttribute('data-group');
        const rows = Array.from(document.querySelectorAll('.rule-row')).filter(row => row.getAttribute('data-group') === group);
        if (!expand) { header.classList.add('group-collapsed'); rows.forEach(r => r.style.display = 'none'); } 
        else { header.classList.remove('group-collapsed'); rows.forEach(r => r.style.display = 'table-row'); }
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
            fetch('/update_agent?name='+name, {method: 'POST'}).then(r => {
                if(r.ok) showToast("指令已发送", "success"); else showToast("发送失败", "warn");
            });
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
        else if(type === 'warning') { btn.className = 'btn warning'; btn.innerText = '确认操作'; icon.innerText = '⚡'; }
        else { btn.className = 'btn'; btn.innerText = '确认执行'; icon.innerText = '✨'; }
        btn.onclick = function() { closeConfirm(); cb(); };
        document.getElementById('confirmModal').style.display = 'block';
    }
    function closeConfirm() { document.getElementById('confirmModal').style.display = 'none'; }

    function genCmd() {
        const n = document.getElementById('agentName').value;
        const t = document.getElementById('addrType').value;
        const arch = document.getElementById('archType').value;
        const p = document.getElementById('connPort').value; 
        const finalDwUrl = dwUrl + "-linux-" + arch;
        const host = (t === "domain") ? (m_domain || location.hostname) : (t === "v4" ? m_v4 : '['+m_v6+']');
        if(!host || host === "[]") { showToast("请先在设置中配置面板地址", "warn"); return; }
        
        let cmd = 'curl -L -o /root/relay '+finalDwUrl+' && chmod +x /root/relay && /root/relay -service install -mode agent -name "'+n+'" -connect "'+host+':'+p+'" -token "'+token+'"';
        if(is_tls) cmd += ' -tls';
        document.getElementById('cmdText').innerText = cmd;
        document.getElementById('cmdText').style.opacity = '1';
        showToast("命令已生成", "success");
    }
    function copyCmd() { copyText(document.getElementById('cmdText').innerText); }

    function delRule(id) { showConfirm("删除规则", "端口将停止服务，确定删除吗？", "danger", () => location.href="/delete?id="+id); }
    function toggleRule(id) { location.href="/toggle?id="+id; }
    function resetTraffic(id) { showConfirm("重置流量", "确定要清零统计数据吗？", "warning", () => location.href="/reset_traffic?id="+id); }

    function openEdit(id, group, note, entry, eport, exit, tip, tport, proto, limit, speed) {
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
        document.getElementById('editModal').style.display = 'block';
    }
    function closeEdit() { document.getElementById('editModal').style.display = 'none'; }
    window.onclick = function(e) { if(e.target.className === 'modal') { closeEdit(); closeConfirm(); document.getElementById('twoFAModal').style.display='none'; } }

    var tempSecret = "";
    function enable2FA() { fetch('/2fa/generate').then(r=>r.json()).then(d => { tempSecret = d.secret; document.getElementById('qrImage').src = d.qr; document.getElementById('twoFAModal').style.display = 'block'; }); }
    function verify2FA() { fetch('/2fa/verify', {method:'POST', body:JSON.stringify({secret:tempSecret, code:document.getElementById('twoFACode').value})}).then(r=>r.json()).then(d => { if(d.success) { showToast("2FA 已开启", "success"); setTimeout(()=>location.reload(), 1000); } else showToast("验证码错误", "warn"); }); }
    function disable2FA() { showConfirm("关闭 2FA", "账户安全性将降低，确定吗？", "danger", () => { fetch('/2fa/disable').then(r=>r.json()).then(d => { if(d.success) location.reload(); }); }); }

    // Chart.js Configuration
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = '#94a3b8';
    
    var ctx = document.getElementById('trafficChart').getContext('2d');
    var txGrad = ctx.createLinearGradient(0, 0, 0, 300);
    txGrad.addColorStop(0, 'rgba(139, 92, 246, 0.2)');
    txGrad.addColorStop(1, 'rgba(139, 92, 246, 0)');
    
    var rxGrad = ctx.createLinearGradient(0, 0, 0, 300);
    rxGrad.addColorStop(0, 'rgba(6, 182, 212, 0.2)');
    rxGrad.addColorStop(1, 'rgba(6, 182, 212, 0)');

    var chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [
                { label: 'Tx', data: Array(30).fill(0), borderColor: '#8b5cf6', backgroundColor: txGrad, borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 },
                { label: 'Rx', data: Array(30).fill(0), borderColor: '#06b6d4', backgroundColor: rxGrad, borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false, backgroundColor: 'rgba(15, 23, 42, 0.9)', titleColor: '#f8fafc', bodyColor: '#cbd5e1', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1, padding: 10, displayColors: true } },
            scales: {
                x: { display: false },
                y: { beginAtZero: true, grid: { color: 'rgba(128, 128, 128, 0.06)', borderDash: [4, 4] }, ticks: { callback: v => formatBytes(v)+'/s', font: {size: 10}, maxTicksLimit: 5 } }
            },
            interaction: { mode: 'nearest', axis: 'x', intersect: false }
        }
    });

    var ctxPie = document.getElementById('pieChart').getContext('2d');
    var pieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{ data: [], backgroundColor: ['#818cf8', '#f472b6', '#fbbf24', '#34d399', '#60a5fa'], borderWidth: 0, hoverOffset: 4 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, usePointStyle: true, padding: 20, font: {size: 11} } } },
            cutout: '75%'
        }
    });

    function updateChartTheme(theme) {
        const gridColor = theme === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';
        chart.options.scales.y.grid.color = gridColor;
        chart.update();
    }

    function formatBytes(b) {
        if(b==0) return "0 B";
        const u = 1024, i = Math.floor(Math.log(b)/Math.log(u));
        return parseFloat((b / Math.pow(u, i)).toFixed(2)) + " " + ["B","KB","MB","GB","TB"][i];
    }
    function formatSpeed(b) {
        if(b<=0) return "0 B/s";
        return formatBytes(b)+"/s";
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
                                if (lastRuleStats[r.id]) {
                                    stx = r.tx - lastRuleStats[r.id].tx;
                                    srx = r.rx - lastRuleStats[r.id].rx;
                                    if(stx < 0) stx = 0; if(srx < 0) srx = 0;
                                }
                                lastRuleStats[r.id] = {tx: r.tx, rx: r.rx};

                                let row = document.getElementById('rule-row-mon-' + r.id);
                                if (!row) {
                                    row = tbody.insertRow();
                                    row.id = 'rule-row-mon-' + r.id;
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
                                }
                                const charts = ruleCharts[r.id];
                                if (charts) {
                                    charts.tx.data.datasets[0].data.push(stx); charts.tx.data.datasets[0].data.shift(); charts.tx.update('none');
                                    charts.rx.data.datasets[0].data.push(srx); charts.rx.data.datasets[0].data.shift(); charts.rx.update('none');
                                }
                            });
                            Array.from(tbody.children).forEach(tr => {
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
                                if(r.status) {
                                    lat.innerHTML = '<span style="color:#10b981;font-weight:600">'+r.latency+' ms</span>';
                                    dot.parentElement.className = 'badge success'; dot.parentElement.innerHTML = '<span class="status-dot pulse"></span> 运行中';
                                } else {
                                    lat.innerHTML = '<span style="color:#ef4444">离线</span>';
                                    dot.parentElement.className = 'badge danger'; dot.parentElement.innerHTML = '<span class="status-dot"></span> 异常';
                                }
                            }
                            if(r.limit > 0) {
                                let pct = (r.total / r.limit) * 100; if(pct > 100) pct = 100;
                                const bar = document.getElementById('rule-bar-'+r.id);
                                if(bar) { bar.style.width = pct + '%'; bar.style.background = pct > 90 ? '#ef4444' : '#6366f1'; }
                                const txt = document.getElementById('rule-limit-text-'+r.id);
                                if(txt) txt.innerText = pct.toFixed(1) + '%';
                            }
                        });
                    }

                    if(d.agents) d.agents.forEach(a => {
                        const loadText = document.getElementById('load-text-'+a.name);
                        const loadBar = document.getElementById('load-bar-'+a.name);
                        if(loadText && loadBar) {
                            let loadStr = a.sys_status; 
                            let loadVal = 0;
                            if(loadStr.includes("Load:")) { loadVal = parseFloat(loadStr.split("|")[0].replace("Load:", "").trim()) || 0; }
                            loadText.innerText = loadVal.toFixed(2);
                            let pct = loadVal * 20; if (pct > 100) pct = 100;
                            loadBar.style.width = pct + "%"; loadBar.style.background = pct > 80 ? "#ef4444" : "#10b981";
                        }
                    });

                    if(d.logs && document.getElementById('logs').classList.contains('active')) {
                        const tbody = document.getElementById('log-table-body');
                        let html = '';
                        d.logs.forEach(l => {
                            html += '<tr><td style="font-family:var(--font-mono);color:var(--text-sub)">'+l.time+'</td>'+
                                    '<td>'+l.ip+'</td>'+
                                    '<td><span class="badge" style="background:var(--input-bg);color:var(--text-main);border:1px solid var(--border)">'+l.action+'</span></td>'+
                                    '<td style="color:var(--text-sub)">'+l.msg+'</td></tr>';
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
</body>
</html>`
