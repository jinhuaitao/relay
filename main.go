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
	DBFile          = "data.db"
	ConfigFile      = "config.json"
	WebPort         = ":8888"
	DownloadURL     = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
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
			c := fmt.Sprintf("[Unit]\nDescription=GoRelay\nAfter=network.target\n[Service]\nType=simple\nExecStart=%s %s\nRestart=always\nUser=root\nLimitNOFILE=1000000\n[Install]\nWantedBy=multi-user.target", exe, args)
			os.WriteFile("/etc/systemd/system/gorelay.service", []byte(c), 0644)
			exec.Command("systemctl", "enable", "gorelay").Run()
			exec.Command("systemctl", "restart", "gorelay").Run()
			log.Println("Systemd 服务已安装")
		} else if isAlpine {
			c := fmt.Sprintf("#!/sbin/openrc-run\nname=\"gorelay\"\ncommand=\"%s\"\ncommand_args=\"%s\"\ncommand_background=true\npidfile=\"/run/gorelay.pid\"\nrc_ulimit=\"-n 1000000\"\ndepend(){ need net; }", exe, args)
			os.WriteFile("/etc/init.d/gorelay", []byte(c), 0755)
			exec.Command("rc-update", "add", "gorelay", "default").Run()
			exec.Command("rc-service", "gorelay", "restart").Run()
			log.Println("OpenRC 服务已安装")
		} else {
			exec.Command("nohup", exe, args, "&").Start()
			log.Println("已通过 nohup 启动")
		}
	} else {
		if isSys {
			exec.Command("systemctl", "disable", "gorelay").Run()
			exec.Command("systemctl", "stop", "gorelay").Run()
			os.Remove("/etc/systemd/system/gorelay.service")
			exec.Command("systemctl", "daemon-reload").Run()
		}
		if isAlpine {
			exec.Command("rc-update", "del", "gorelay", "default").Run()
			exec.Command("rc-service", "gorelay", "stop").Run()
			os.Remove("/etc/init.d/gorelay")
		}
		log.Println("服务已卸载")
	}
}

func doSelfUninstall() {
	log.Println("执行自毁程序...")
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		exec.Command("systemctl", "disable", "gorelay").Run()
		os.Remove("/etc/systemd/system/gorelay.service")
		exec.Command("systemctl", "daemon-reload").Run()
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		exec.Command("rc-update", "del", "gorelay", "default").Run()
		os.Remove("/etc/init.d/gorelay")
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
		// 预先检查证书，决定是否启用 TLS
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

		// 从配置中读取端口列表，默认 9999
		portsStr := config.AgentPorts
		if portsStr == "" {
			portsStr = "9999"
		}
		ports := strings.Split(portsStr, ",")

		// 循环监听多个端口
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
	http.HandleFunc("/restart", authMiddleware(handleRestart)) // 新增重启路由

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
	}{al, displayRules, displayLogs, conf.AgentToken, conf.WebUser, DownloadURL, totalTraffic, conf.MasterIP, conf.MasterIPv6, conf.MasterDomain, conf, conf.TwoFAEnabled, isMasterTLS, cleanPorts}

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

func doRestart() {
	log.Println("🔄 接收到重启指令...")
	// 1. 尝试 Systemd
	if _, err := os.Stat("/etc/systemd/system/relay.service"); err == nil {
		exec.Command("systemctl", "restart", "relay").Start()
		time.Sleep(1 * time.Second)
		os.Exit(0)
		return
	}
	// 2. 尝试 OpenRC
	if _, err := os.Stat("/etc/init.d/relay"); err == nil {
		exec.Command("rc-service", "relay", "restart").Start()
		time.Sleep(1 * time.Second)
		os.Exit(0)
		return
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

func checkTargetHealth(conn net.Conn) {
	var results []HealthReport
	activeTargets.Range(func(key, value interface{}) bool {
		targets := strings.Split(value.(string), ",")
		var bestLat int64 = -1
		for _, target := range targets {
			target = strings.TrimSpace(target)
			start := time.Now()
			c, err := net.DialTimeout("tcp", target, 2*time.Second)
			if err == nil {
				c.Close()
				lat := time.Since(start).Milliseconds()
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
		json.NewEncoder(conn).Encode(Message{Type: "health", Payload: results})
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
	host, _, _ := net.SplitHostPort(addr)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refs[host]--
	if t.refs[host] <= 0 {
		delete(t.refs, host)
		atomic.AddInt64(t.count, -1)
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
<style>
:root { --primary: #6366f1; --bg: #0f172a; --text: #f8fafc; --text-sub: #94a3b8; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background-image: radial-gradient(circle at top right, #312e81, transparent 40%), radial-gradient(circle at bottom left, #1e1b4b, transparent 40%); }
.card { background: rgba(30, 41, 59, 0.6); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 40px; border-radius: 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); width: 100%; max-width: 400px; border: 1px solid rgba(255,255,255,0.1); }
h2 { text-align: center; margin: 0 0 10px 0; font-size: 26px; font-weight: 800; background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
p { text-align: center; color: var(--text-sub); margin-bottom: 30px; font-size: 14px; line-height: 1.5; }
.input-group { margin-bottom: 20px; position: relative; }
.input-group i { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: var(--text-sub); transition: .3s; }
input { width: 100%; padding: 14px 14px 14px 44px; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; background: rgba(15, 23, 42, 0.6); color: var(--text); outline: none; transition: .3s; box-sizing: border-box; font-size: 14px; }
input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); background: rgba(15, 23, 42, 0.9); }
input:focus + i { color: var(--primary); }
button { width: 100%; padding: 14px; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: .3s; box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.3); display: flex; align-items: center; justify-content: center; gap: 8px; }
button:hover { transform: translateY(-2px); box-shadow: 0 20px 25px -5px rgba(99, 102, 241, 0.4); }
</style>
</head>
<body>
<form class="card" method="POST">
    <h2>GoRelay Pro</h2>
    <p>欢迎使用，请配置初始管理员账户<br>并设置通信 Token 密钥</p>
    <div class="input-group"><input name="username" placeholder="设置管理员用户名" required autocomplete="off"><i class="ri-user-line"></i></div>
    <div class="input-group"><input type="password" name="password" placeholder="设置登录密码" required><i class="ri-lock-password-line"></i></div>
    <div class="input-group"><input name="token" placeholder="设置通信 Token (Agent 连接密钥)" required><i class="ri-key-2-line"></i></div>
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
<style>
:root { --primary: #6366f1; --bg: #020617; --text: #f8fafc; --text-sub: #94a3b8; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; position: relative; }
.bg-glow { position: absolute; width: 600px; height: 600px; background: radial-gradient(circle, rgba(99,102,241,0.1) 0%, rgba(0,0,0,0) 70%); top: -10%; left: -10%; z-index: -1; animation: float 10s infinite ease-in-out; }
.bg-glow-2 { position: absolute; width: 500px; height: 500px; background: radial-gradient(circle, rgba(168,85,247,0.1) 0%, rgba(0,0,0,0) 70%); bottom: -10%; right: -10%; z-index: -1; animation: float 10s infinite ease-in-out reverse; }
@keyframes float { 0%,100%{transform:translate(0,0)} 50%{transform:translate(30px, 30px)} }

.card { background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); padding: 48px 40px; border-radius: 24px; width: 100%; max-width: 360px; border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
.header { text-align: center; margin-bottom: 32px; }
.logo-icon { font-size: 48px; margin-bottom: 10px; display: inline-block; background: linear-gradient(135deg, #818cf8, #c084fc); -webkit-background-clip: text; color: transparent; filter: drop-shadow(0 0 10px rgba(99,102,241,0.3)); }
.header h2 { margin: 0; font-size: 24px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
.header p { margin: 8px 0 0; color: var(--text-sub); font-size: 14px; }

.input-box { margin-bottom: 20px; position: relative; }
.input-box i { position: absolute; left: 16px; top: 15px; color: var(--text-sub); font-size: 18px; transition: .3s; }
input { width: 100%; padding: 14px 14px 14px 48px; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; font-size: 15px; outline: none; transition: .3s; box-sizing: border-box; }
input:focus { border-color: var(--primary); background: rgba(15, 23, 42, 0.8); box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.15); }
input:focus + i { color: var(--primary); }

button { width: 100%; padding: 14px; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: .3s; margin-top: 10px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); display: flex; align-items: center; justify-content: center; gap: 8px; }
button:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.4); }
.error-msg { background: rgba(239, 68, 68, 0.1); color: #ef4444; padding: 12px; border-radius: 10px; font-size: 13px; margin-bottom: 24px; text-align: center; border: 1px solid rgba(239, 68, 68, 0.2); display: flex; align-items: center; justify-content: center; gap: 6px; animation: shake 0.4s ease-in-out; }
@keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-5px)} 75%{transform:translateX(5px)} }
</style>
</head>
<body>
<div class="bg-glow"></div><div class="bg-glow-2"></div>
<form class="card" method="POST">
    <div class="header">
        <i class="ri-globe-line logo-icon"></i>
        <h2>GoRelay Pro</h2>
        <p>安全内网穿透控制台</p>
    </div>
    {{if .Error}}<div class="error-msg"><i class="ri-error-warning-fill"></i> {{.Error}}</div>{{end}}
    
    <div class="input-box"><input name="username" placeholder="管理员账号" required autocomplete="off"><i class="ri-user-3-line"></i></div>
    <div class="input-box"><input type="password" name="password" placeholder="登录密码" required><i class="ri-lock-2-line"></i></div>
    {{if .TwoFA}}
    <div class="input-box"><input name="code" placeholder="2FA 动态验证码" required pattern="[0-9]{6}" maxlength="6" style="letter-spacing: 2px; text-align: center; padding-left: 14px;"><i class="ri-shield-keyhole-line" style="left: auto; right: 16px;"></i></div>
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
<title>GoRelay Pro 仪表盘</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
/* --- 现代 CSS 变量定义 --- */
:root {
    --primary: #818cf8; --primary-hover: #6366f1; --primary-light: rgba(129, 140, 248, 0.15);
    --bg-body: #f8fafc; --bg-sidebar: #ffffff; --bg-card: #ffffff;
    --text-main: #1e293b; --text-sub: #64748b; --text-inv: #ffffff;
    --border: #e2e8f0; --input-bg: #f1f5f9;
    --success: #10b981; --success-bg: rgba(16, 185, 129, 0.1); --success-text: #059669;
    --danger: #ef4444; --danger-bg: rgba(239, 68, 68, 0.1); --danger-text: #dc2626;
    --warning: #f59e0b; --warning-bg: rgba(245, 158, 11, 0.1); --warning-text: #d97706;
    --radius: 20px;
    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.02);
    --sidebar-w: 280px;
    --trans: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}
[data-theme="dark"] {
    --primary: #818cf8;
    --bg-body: #020617; --bg-sidebar: #0f172a; --bg-card: rgba(30, 41, 59, 0.4);
    --text-main: #f1f5f9; --text-sub: #94a3b8;
    --border: rgba(255,255,255,0.06); --input-bg: rgba(15, 23, 42, 0.6);
    --success-bg: rgba(16, 185, 129, 0.15); --success-text: #34d399;
    --danger-bg: rgba(239, 68, 68, 0.15); --danger-text: #f87171;
    --warning-bg: rgba(245, 158, 11, 0.15); --warning-text: #fbbf24;
    --shadow-sm: none; --shadow-md: none; --shadow-lg: none;
}

/* --- 全局样式 --- */
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; outline: none; }
body { margin: 0; font-family: 'Inter', system-ui, sans-serif; background: var(--bg-body); color: var(--text-main); height: 100vh; display: flex; overflow: hidden; font-size: 14px; letter-spacing: -0.01em; }
/* 背景装饰 */
body::before { content: ''; position: fixed; top: -10%; left: -10%; width: 50%; height: 50%; background: radial-gradient(circle, rgba(99,102,241,0.08) 0%, transparent 60%); z-index: -1; pointer-events: none; filter: blur(60px); }
body::after { content: ''; position: fixed; bottom: -10%; right: -10%; width: 50%; height: 50%; background: radial-gradient(circle, rgba(168,85,247,0.08) 0%, transparent 60%); z-index: -1; pointer-events: none; filter: blur(60px); }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-sub); }

/* --- 侧边栏 --- */
.sidebar { width: var(--sidebar-w); background: var(--bg-sidebar); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; z-index: 50; backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); }
.brand { height: 80px; display: flex; align-items: center; padding: 0 28px; font-size: 20px; font-weight: 800; gap: 12px; background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.brand i { font-size: 28px; color: #818cf8; -webkit-text-fill-color: initial; }

.menu { flex: 1; padding: 20px 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 6px; }
.item { display: flex; align-items: center; padding: 12px 16px; color: var(--text-sub); cursor: pointer; border-radius: 12px; transition: var(--trans); font-weight: 500; position: relative; overflow: hidden; }
.item:hover { background: var(--primary-light); color: var(--primary); }
.item.active { background: var(--primary); color: #fff; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); }
.item i { margin-right: 12px; font-size: 20px; }

.user-panel { padding: 24px; border-top: 1px solid var(--border); }
.user-card { display: flex; align-items: center; gap: 14px; margin-bottom: 16px; background: var(--input-bg); padding: 12px; border-radius: 16px; border: 1px solid var(--border); }
.avatar { width: 42px; height: 42px; background: linear-gradient(135deg, #818cf8, #4f46e5); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 700; font-size: 18px; box-shadow: 0 4px 10px rgba(99,102,241,0.3); }
.btn-logout { width: 100%; padding: 10px; border-radius: 10px; border: 1px solid rgba(239,68,68,0.2); background: rgba(239,68,68,0.05); color: #ef4444; cursor: pointer; font-size: 13px; display: flex; align-items: center; justify-content: center; gap: 6px; transition: var(--trans); text-decoration: none; font-weight: 600; }
.btn-logout:hover { background: rgba(239,68,68,0.1); transform: translateY(-1px); }

/* --- 主内容区 --- */
.main { flex: 1; display: flex; flex-direction: column; position: relative; width: 100%; min-width: 0; }
.header { height: 80px; display: flex; align-items: center; justify-content: space-between; padding: 0 40px; z-index: 40; }
.page-title { font-weight: 800; font-size: 26px; display: flex; align-items: center; gap: 12px; color: var(--text-main); }

.theme-toggle { width: 42px; height: 42px; border-radius: 12px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text-sub); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: var(--trans); backdrop-filter: blur(10px); }
.theme-toggle:hover { border-color: var(--primary); color: var(--primary); box-shadow: 0 0 15px var(--primary-light); transform: rotate(15deg); }

.content { flex: 1; padding: 0 40px 40px 40px; overflow-y: auto; overflow-x: hidden; scroll-behavior: smooth; }
.page { display: none; max-width: 1400px; margin: 0 auto; animation: slideUp 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
.page.active { display: block; }
@keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

/* --- 卡片组件 (Glassmorphism) --- */
.card { background: var(--bg-card); padding: 28px; border-radius: var(--radius); box-shadow: var(--shadow-lg); border: 1px solid var(--border); margin-bottom: 24px; position: relative; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); transition: transform 0.2s, border-color 0.2s; }
[data-theme="dark"] .card { background: rgba(30, 41, 59, 0.4); border-top: 1px solid rgba(255,255,255,0.08); }
.card:hover { border-color: rgba(129, 140, 248, 0.3); }

h3 { margin: 0 0 24px 0; font-size: 16px; color: var(--text-main); font-weight: 700; display: flex; align-items: center; gap: 10px; }
h3 i { color: var(--primary); background: var(--primary-light); padding: 8px; border-radius: 10px; font-size: 18px; }

/* 统计卡片 */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 24px; margin-bottom: 32px; }
.stat-item { padding: 24px; display: flex; flex-direction: column; justify-content: space-between; position: relative; overflow: hidden; height: 150px; border: 1px solid var(--border); border-radius: 20px; background: linear-gradient(145deg, var(--bg-card) 0%, rgba(99,102,241,0.02) 100%); transition: transform 0.2s; }
.stat-item:hover { transform: translateY(-4px); box-shadow: 0 10px 20px -5px rgba(0,0,0,0.1); }
.stat-item::before { content: ''; position: absolute; right: -30px; top: -30px; width: 120px; height: 120px; background: currentColor; opacity: 0.06; border-radius: 50%; filter: blur(40px); }
.stat-item i.bg-icon { position: absolute; right: 20px; bottom: 20px; font-size: 72px; opacity: 0.04; transform: rotate(-15deg); pointer-events: none; }
.stat-label { color: var(--text-sub); font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }
.stat-val { font-size: 36px; font-weight: 800; color: var(--text-main); letter-spacing: -1px; z-index: 1; font-family: 'Inter', sans-serif; }
.stat-trend { font-size: 13px; margin-top: auto; display: flex; align-items: center; gap: 6px; font-weight: 500; opacity: 0.8; }

.dashboard-grid { display: grid; grid-template-columns: 2.5fr 1fr; gap: 24px; margin-bottom: 24px; }
/* 图表容器自适应 */
.chart-box { height: 360px; width: 100%; position: relative; }

@media (max-width: 1100px) { .dashboard-grid { grid-template-columns: 1fr; } }

/* 表格优化 */
.table-container { overflow-x: auto; border-radius: 16px; border: 1px solid var(--border); background: var(--bg-card); }
table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; }
th { text-align: left; padding: 18px 24px; color: var(--text-sub); font-size: 12px; font-weight: 600; text-transform: uppercase; background: var(--input-bg); border-bottom: 1px solid var(--border); }
td { padding: 16px 24px; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--text-main); vertical-align: middle; transition: background 0.2s; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--input-bg); }

/* 分组标题设计 */
.group-header { background: linear-gradient(90deg, var(--primary-light) 0%, transparent 100%); cursor: pointer; user-select: none; position: relative; }
.group-header:hover { background: rgba(129, 140, 248, 0.2); }
.group-header td { padding: 12px 24px; font-weight: 700; color: var(--primary); font-size: 13px; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); border-left: 3px solid var(--primary); }
.group-icon { transition: transform 0.2s; display: inline-block; margin-right: 8px; width: 16px; text-align: center; }
.group-collapsed .group-icon { transform: rotate(-90deg); }

/* 状态徽标 */
.badge { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; border: 1px solid transparent; letter-spacing: 0.3px; }
.badge.success { background: var(--success-bg); color: var(--success-text); border-color: rgba(16,185,129,0.1); }
.badge.danger { background: var(--danger-bg); color: var(--danger-text); border-color: rgba(239,68,68,0.1); }
.badge.warning { background: var(--warning-bg); color: var(--warning-text); border-color: rgba(245,158,11,0.1); }
.status-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; position: relative; background: currentColor; box-shadow: 0 0 0 2px rgba(255,255,255,0.1); }
.status-dot.pulse { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); animation: pulse-shadow 2s infinite; }
@keyframes pulse-shadow { 0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); } 70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); } 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); } }

/* 表单与按钮 */
.grid-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; align-items: end; }
.form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 10px; color: var(--text-sub); }
input, select { width: 100%; padding: 12px 16px; border: 1px solid var(--border); border-radius: 12px; background: var(--input-bg); color: var(--text-main); font-size: 14px; outline: none; transition: 0.2s; font-family: inherit; }
input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 4px var(--primary-light); background: var(--bg-card); }

.btn { background: var(--primary); color: #fff; border: none; padding: 12px 24px; border-radius: 12px; cursor: pointer; font-size: 14px; font-weight: 600; transition: 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px; text-decoration: none; box-shadow: 0 4px 10px -2px rgba(99, 102, 241, 0.4); }
.btn:hover { background: var(--primary-hover); transform: translateY(-2px); box-shadow: 0 8px 15px -3px rgba(99, 102, 241, 0.5); }
.btn:active { transform: translateY(0); }
.btn.secondary { background: transparent; border: 1px solid var(--border); color: var(--text-main); box-shadow: none; }
.btn.secondary:hover { background: var(--input-bg); border-color: var(--text-sub); color: var(--primary); }
.btn.danger { background: var(--danger-bg); color: var(--danger-text); border: 1px solid rgba(239,68,68,0.2); box-shadow: none; }
.btn.danger:hover { background: var(--danger); color: #fff; border-color: transparent; }
.btn.warning { background: var(--warning-bg); color: var(--warning-text); border: 1px solid rgba(245,158,11,0.2); box-shadow: none; }
.btn.warning:hover { background: var(--warning); color: #fff; border-color: transparent; }
.btn.icon { padding: 0; width: 36px; height: 36px; border-radius: 10px; font-size: 18px; }

/* 进度条 */
.progress { width: 100%; height: 6px; background: var(--border); border-radius: 10px; overflow: hidden; margin-top: 10px; position: relative; }
.progress-bar { height: 100%; background: var(--primary); border-radius: 10px; transition: width 0.5s ease; box-shadow: 0 0 10px var(--primary-light); position: relative; overflow: hidden; }
.progress-bar::after { content: ''; position: absolute; top: 0; left: 0; bottom: 0; right: 0; background-image: linear-gradient(45deg,rgba(255,255,255,.15) 25%,transparent 25%,transparent 50%,rgba(255,255,255,.15) 50%,rgba(255,255,255,.15) 75%,transparent 75%,transparent); background-size: 1rem 1rem; animation: progress-stripes 1s linear infinite; }
@keyframes progress-stripes { from { background-position: 1rem 0; } to { background-position: 0 0; } }

/* 终端窗口样式 */
.terminal-window { background: #1e293b; border-radius: 16px; box-shadow: var(--shadow-lg); overflow: hidden; border: 1px solid #334155; font-family: 'JetBrains Mono', monospace; }
.terminal-header { background: #0f172a; padding: 12px 16px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #334155; }
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot.red { background: #ef4444; } .dot.yellow { background: #f59e0b; } .dot.green { background: #10b981; }
.terminal-body { padding: 24px; color: #e2e8f0; font-size: 13px; line-height: 1.6; word-break: break-all; position: relative; }
.cmd-content { opacity: 0.9; }
.copy-overlay { position: absolute; top: 12px; right: 12px; }

/* 模态框 */
.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(8px); animation: fadeIn 0.2s; }
.modal-content { background: var(--bg-card); margin: 8vh auto; padding: 40px; border-radius: 24px; width: 90%; max-width: 580px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); border: 1px solid var(--border); transform: scale(0.95); animation: scaleIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards; position: relative; max-height: 85vh; overflow-y: auto; }
@keyframes scaleIn { to { transform: scale(1); opacity: 1; } }
.close-modal { position: absolute; right: 24px; top: 24px; font-size: 24px; cursor: pointer; color: var(--text-sub); transition: .2s; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: var(--input-bg); }
.close-modal:hover { color: var(--text-main); transform: rotate(90deg); background: var(--border); }

/* 移动端适配 */
.mobile-nav { display: none; }
@media (max-width: 768px) {
    .sidebar { display: none; }
    .header { padding: 0 20px; height: 64px; }
    .content { padding: 20px 20px 90px 20px; } /* 移动端 padding 调小 */
    .stats-grid { grid-template-columns: 1fr; }
    .mobile-nav { display: flex; position: fixed; bottom: 0; left: 0; width: 100%; background: rgba(var(--bg-card), 0.9); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-top: 1px solid var(--border); height: 64px; z-index: 100; justify-content: space-around; padding-bottom: env(safe-area-inset-bottom); align-items: center; }
    .nav-btn { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--text-sub); font-size: 10px; gap: 4px; height: 100%; transition: .2s; }
    .nav-btn.active { color: var(--primary); }
    .nav-btn.active i { transform: translateY(-2px); }
    .nav-btn i { font-size: 22px; transition: .2s; }
    .card { padding: 20px; } /* 移动端卡片内边距调小 */
    .chart-box { height: 240px; } /* 移动端图表高度恢复紧凑 */
    .dashboard-grid { display: block; }
}

/* Toast */
.toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(20px); background: rgba(15, 23, 42, 0.95); color: #fff; padding: 12px 24px; border-radius: 50px; font-size: 14px; opacity: 0; visibility: hidden; transition: 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index: 2000; display: flex; align-items: center; gap: 10px; backdrop-filter: blur(10px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); }
.toast.show { opacity: 1; visibility: visible; transform: translateX(-50%) translateY(0); bottom: 100px; }
</style>
</head>
<body>

<div id="toast" class="toast"><i id="t-icon"></i><span id="t-msg"></span></div>

<div class="sidebar">
    <div class="brand"><i class="ri-globe-line"></i> GoRelay Pro</div>
    <div class="menu">
        <div class="item active" onclick="nav('dashboard',this)"><i class="ri-dashboard-3-line"></i> 概览监控</div>
        <div class="item" onclick="nav('rules',this)"><i class="ri-route-line"></i> 转发管理</div>
        <div class="item" onclick="nav('deploy',this)"><i class="ri-rocket-2-line"></i> 节点部署</div>
        <div class="item" onclick="nav('logs',this)"><i class="ri-file-list-3-line"></i> 系统日志</div>
        <div class="item" onclick="nav('settings',this)"><i class="ri-settings-4-line"></i> 系统设置</div>
    </div>
    <div class="user-panel">
        <div class="user-card">
            <div class="avatar">{{printf "%.1s" .User}}</div>
            <div style="flex:1">
                <div style="font-weight:700;font-size:14px">{{.User}}</div>
                <div style="font-size:12px;opacity:0.6;margin-top:2px">管理员在线</div>
            </div>
        </div>
        <a href="/logout" class="btn-logout"><i class="ri-logout-box-r-line"></i> 安全退出</a>
    </div>
</div>

<div class="main">
    <header class="header">
        <div class="page-title"><span id="page-text">仪表盘</span></div>
        <div style="display:flex;gap:16px;align-items:center">
            <a href="https://github.com/jinhuaitao/relay" target="_blank" class="theme-toggle" title="项目源码"><i class="ri-github-line"></i></a>
            <div class="theme-toggle" onclick="toggleTheme()"><i class="ri-moon-line" id="theme-icon"></i></div>
        </div>
    </header>

    <div class="content">
        <div id="dashboard" class="page active">
            <div class="stats-grid">
                <div class="card stat-item" style="color:#818cf8">
                    <div>
                        <div class="stat-label">累计总流量</div>
                        <div class="stat-val" id="stat-total-traffic">{{formatBytes .TotalTraffic}}</div>
                    </div>
                    <div class="stat-trend"><i class="ri-database-2-line"></i> 数据中继总量</div>
                    <i class="ri-arrow-up-down-line bg-icon"></i>
                </div>
                <div class="card stat-item" style="color:#06b6d4">
                    <div>
                        <div class="stat-label">实时下载 (Rx)</div>
                        <div class="stat-val" id="speed-rx">0 B/s</div>
                    </div>
                    <div class="stat-trend"><i class="ri-download-2-line"></i> 当前下行带宽</div>
                    <i class="ri-speed-line bg-icon"></i>
                </div>
                <div class="card stat-item" style="color:#8b5cf6">
                    <div>
                        <div class="stat-label">实时上传 (Tx)</div>
                        <div class="stat-val" id="speed-tx">0 B/s</div>
                    </div>
                    <div class="stat-trend"><i class="ri-upload-2-line"></i> 当前上行带宽</div>
                    <i class="ri-upload-cloud-line bg-icon"></i>
                </div>
                <div class="card stat-item" style="color:#10b981">
                    <div>
                        <div class="stat-label">在线节点</div>
                        <div class="stat-val">{{len .Agents}} <span style="font-size:16px;opacity:0.6;font-weight:600">/ {{len .Rules}}</span></div>
                    </div>
                    <div class="stat-trend"><i class="ri-server-line"></i> 活跃/规则总数</div>
                    <i class="ri-cpu-line bg-icon"></i>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="card">
                    <h3><i class="ri-pulse-line"></i> 实时全网流量监控</h3>
                    <div class="chart-box"><canvas id="trafficChart"></canvas></div>
                </div>
                <div class="card">
                    <h3><i class="ri-pie-chart-line"></i> 规则流量分布 (Top 5)</h3>
                    <div class="chart-box" style="display:flex;justify-content:center"><canvas id="pieChart"></canvas></div>
                </div>
            </div>

            <div class="card">
                <h3><i class="ri-server-line"></i> 节点状态监控</h3>
                <div class="table-container">
                    {{if .Agents}}
                    <table>
                        <thead><tr><th>状态</th><th>节点名称 / 标识</th><th>远程 IP</th><th>系统负载 (Load)</th><th>操作</th></tr></thead>
                        <tbody>
                        {{range .Agents}}
                        <tr>
                            <td><span class="badge success"><span class="status-dot pulse"></span> 在线</span></td>
                            <td><div style="font-weight:700">{{.Name}}</div></td>
                            <td><span class="click-copy" onclick="copyText('{{.RemoteIP}}')" style="font-family:'JetBrains Mono';background:var(--input-bg);padding:4px 8px;border-radius:6px;font-size:12px;cursor:pointer" title="点击复制">{{.RemoteIP}}</span></td>
                            <td style="width:240px">
                                <div style="display:flex;align-items:center;gap:12px">
                                    <div class="progress" style="margin:0;flex:1"><div class="progress-bar" id="load-bar-{{.Name}}" style="width:0%"></div></div>
                                    <span id="load-text-{{.Name}}" style="font-size:12px;font-family:'JetBrains Mono';min-width:60px;text-align:right">0.0</span>
                                </div>
                            </td>
                            <td><button class="btn danger icon" onclick="delAgent('{{.Name}}')" title="卸载节点"><i class="ri-delete-bin-line"></i></button></td>
                        </tr>
                        {{end}}
                        </tbody>
                    </table>
                    {{else}}
                    <div style="padding:60px 0;text-align:center;color:var(--text-sub)">
                        <div style="background:var(--input-bg);width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px auto;font-size:32px"><i class="ri-ghost-line"></i></div>
                        暂无在线节点，请前往“部署”页面添加
                    </div>
                    {{end}}
                </div>
            </div>
        </div>

        <div id="rules" class="page">
            <div class="card">
                <h3><i class="ri-add-circle-line"></i> 新建转发规则</h3>
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
                <h3><i class="ri-list-check"></i> 规则列表</h3>
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
                                    <i class="ri-folder-open-line"></i> 
                                    {{if .Group}}{{.Group}}{{else}}默认分组{{end}}
                                </td>
                            </tr>
                            {{$currentGroup = .Group}}
                        {{end}}
                        <tr class="rule-row" data-group="{{.Group}}" style="{{if .Disabled}}opacity:0.6;filter:grayscale(1);{{end}}">
                            <td>
                                <div style="font-weight:700;font-size:15px;margin-bottom:6px">{{if .Note}}{{.Note}}{{else}}未命名规则{{end}}</div>
                                <div style="font-size:12px;color:var(--text-sub);display:flex;align-items:center;gap:6px">
                                    <span style="background:var(--input-bg);padding:2px 8px;border-radius:6px;border:1px solid var(--border)">{{.EntryAgent}}:{{.EntryPort}}</span> 
                                    <i class="ri-arrow-right-line" style="color:var(--primary);font-size:12px"></i> 
                                    <span style="background:var(--input-bg);padding:2px 8px;border-radius:6px;border:1px solid var(--border)">{{.ExitAgent}}</span>
                                </div>
                            </td>
                            <td>
                                <div style="font-family:'JetBrains Mono';font-size:13px">{{.TargetIP}}:{{.TargetPort}}</div>
                                <div style="font-size:12px;margin-top:4px;display:flex;align-items:center;gap:5px" id="rule-latency-{{.ID}}"><i class="ri-loader-4-line ri-spin"></i> 检测中...</div>
                            </td>
                            <td style="min-width:200px">
                                <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px">
                                    <span><i class="ri-user-line"></i> <span id="rule-uc-{{.ID}}">{{.UserCount}}</span> 连接</span>
                                    <span id="rule-traffic-{{.ID}}" style="font-family:'JetBrains Mono';font-weight:600">{{formatBytes (add .TotalTx .TotalRx)}}</span>
                                </div>
                                {{if gt .TrafficLimit 0}}
                                <div class="progress"><div id="rule-bar-{{.ID}}" class="progress-bar" style="width:{{percent .TotalTx .TotalRx .TrafficLimit}}%"></div></div>
                                <div style="font-size:11px;color:var(--text-sub);margin-top:4px;display:flex;justify-content:space-between">
                                    <span id="rule-limit-text-{{.ID}}">已用 {{percent .TotalTx .TotalRx .TrafficLimit | printf "%.1f"}}%</span>
                                    <span>限 {{formatBytes .TrafficLimit}}</span>
                                </div>
                                {{else}}
                                <div class="progress"><div class="progress-bar" style="width:100%;background:var(--success)"></div></div>
                                <div style="font-size:11px;color:var(--text-sub);margin-top:4px"><i class="ri-infinite-line"></i> 无流量限制</div>
                                {{end}}
                            </td>
                            <td>
                                {{if .Disabled}}<span class="badge" style="background:var(--input-bg);color:var(--text-sub)">已暂停</span>
                                {{else if and (gt .TrafficLimit 0) (ge (add .TotalTx .TotalRx) .TrafficLimit)}}<span class="badge danger">流量耗尽</span>
                                {{else}}<span class="badge success"><span class="status-dot pulse" id="rule-status-dot-{{.ID}}"></span> 运行中</span>{{end}}
                                <div style="font-size:11px;color:var(--text-sub);margin-top:4px;opacity:0.8">{{if gt .SpeedLimit 0}}限速 {{formatSpeed .SpeedLimit}}{{else}}全速模式{{end}}</div>
                            </td>
                            <td>
                                <div style="display:flex;gap:8px">
                                    <button class="btn icon secondary" onclick="toggleRule('{{.ID}}')" title="切换状态">{{if .Disabled}}<i class="ri-play-fill" style="color:var(--success)"></i>{{else}}<i class="ri-pause-fill" style="color:var(--warning)"></i>{{end}}</button>
                                    <button class="btn icon secondary" onclick="openEdit('{{.ID}}','{{.Group}}','{{.Note}}','{{.EntryAgent}}','{{.EntryPort}}','{{.ExitAgent}}','{{.TargetIP}}','{{.TargetPort}}','{{.Protocol}}','{{.TrafficLimit}}','{{.SpeedLimit}}')" title="编辑"><i class="ri-edit-line"></i></button>
                                    <button class="btn icon secondary" onclick="resetTraffic('{{.ID}}')" title="重置流量"><i class="ri-refresh-line"></i></button>
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
                <h3><i class="ri-install-line"></i> 节点安装向导</h3>
                <p style="color:var(--text-sub);font-size:14px;line-height:1.6;max-width:800px">
                    请在您的 VPS 或服务器（支持 Linux/macOS）上执行以下命令以安装 Agent 客户端。Agent 安装后将自动连接至本面板。
                </p>
                
                <div style="background:var(--input-bg);padding:32px;border-radius:20px;border:1px solid var(--border);margin-top:20px">
                    <div class="grid-form" style="margin-bottom:24px">
                        <div class="form-group"><label>1. 给节点起个名字</label><input id="agentName" value="Node-01"></div>
                        <div class="form-group"><label>2. 选择连接方式</label><select id="addrType"><option value="domain">使用域名 ({{.MasterDomain}})</option><option value="v4">使用 IPv4 ({{.MasterIP}})</option><option value="v6">使用 IPv6 ({{.MasterIPv6}})</option></select></div>
                        <div class="form-group">
                            <label>3. 通信端口</label>
                            <select id="connPort">
                                {{range .Ports}}<option value="{{.}}">{{.}}</option>{{end}}
                                <option disabled>──────────</option>
                                <option disabled value="">(更多端口请去系统设置)</option>
                            </select>
                        </div>
                        <div class="form-group"><label>4. 目标机器架构</label><select id="archType"><option value="amd64">Linux AMD64 (x86_64)</option><option value="arm64">Linux ARM64 (aarch64)</option></select></div>
                    </div>
                    <button class="btn" onclick="genCmd()"><i class="ri-magic-line"></i> 生成安装命令</button>
                    
                    <div class="terminal-window" style="margin-top:24px">
                        <div class="terminal-header">
                            <div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div>
                            <span style="color:#64748b;font-size:12px;margin-left:10px"></span>
                        </div>
                        <div class="terminal-body">
                            <div class="copy-overlay"><button class="btn icon secondary" style="background:rgba(255,255,255,0.1);color:#fff;border:none" onclick="copyCmd()" title="复制"><i class="ri-file-copy-line"></i></button></div>
                            <span style="color:#10b981">root@server:~$</span> <span id="cmdText" class="cmd-content">请先点击上方按钮生成命令...</span><span class="cursor" style="animation:blink 1s infinite"></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="logs" class="page">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px">
                    <h3><i class="ri-history-line"></i> 系统操作日志</h3>
                    <a href="/export_logs" class="btn secondary" style="text-decoration:none;font-size:13px"><i class="ri-download-line"></i> 导出 JSON</a>
                </div>
                <div class="table-container">
                    <table>
                        <thead><tr><th>时间</th><th>IP 来源</th><th>操作类型</th><th>详情内容</th></tr></thead>
                        <tbody id="log-table-body">
                        {{range .Logs}}
                        <tr>
                            <td style="font-family:'JetBrains Mono';color:var(--text-sub)">{{.Time}}</td>
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
            <div class="card" style="max-width:900px">
                <h3><i class="ri-settings-line"></i> 系统全局配置</h3>
                <form action="/update_settings" method="POST">
                    <div class="grid-form" style="grid-template-columns: 1fr; gap:24px">
                        
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
                            <div class="form-group"><label>修改管理员密码</label><input type="password" name="password" placeholder="留空则不修改"></div>
                            <div class="form-group"><label>通信 Token (Agent 密钥)</label><input name="token" value="{{.Token}}"></div>
                        </div>

                        <div style="background:rgba(129,140,248,0.05);padding:20px;border-radius:16px;border:1px dashed var(--primary);grid-column:1/-1">
                            <h4 style="margin:0 0 10px 0;font-size:14px;color:var(--primary)"><i class="ri-server-line"></i> Agent 通信端口配置</h4>
                            <div class="form-group" style="margin:0">
                                <label style="font-weight:400">设置 Master 监听的端口 (多个端口请用英文逗号分隔，例如: 9999,10086)</label>
                                <input name="agent_ports" value="{{if .Config.AgentPorts}}{{.Config.AgentPorts}}{{else}}9999{{end}}" placeholder="9999">
                                <div style="font-size:12px;color:var(--warning-text);margin-top:6px;display:flex;align-items:center;gap:4px"><i class="ri-alert-line"></i> 修改此处端口后，必须手动重启服务才能生效！</div>
                            </div>
                        </div>
                        
                        <div style="background:rgba(99,102,241,0.05);padding:24px;border-radius:16px;border:1px solid rgba(99,102,241,0.2);grid-column:1/-1">
                            <h4 style="margin:0 0 16px 0;font-size:15px;color:var(--primary)"><i class="ri-telegram-line"></i> Telegram 消息通知</h4>
                            <div class="grid-form" style="gap:16px;grid-template-columns: 1fr 1fr;">
                                <div class="form-group"><label>Bot Token</label><input name="tg_bot_token" value="{{.Config.TgBotToken}}" placeholder="123456:ABC-DEF..."></div>
                                <div class="form-group"><label>Chat ID</label><input name="tg_chat_id" value="{{.Config.TgChatID}}" placeholder="-100xxxxxxx"></div>
                            </div>
                        </div>

                        <div style="background:var(--input-bg);padding:24px;border-radius:16px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;grid-column:1/-1">
                            <div>
                                <h4 style="margin:0 0 6px 0;font-size:14px"><i class="ri-shield-keyhole-line"></i> 双因素认证 (2FA)</h4>
                                <div style="font-size:12px;color:var(--text-sub)">推荐开启。登录时需验证 Google Authenticator 动态码。</div>
                            </div>
                            <div>
                                {{if .Config.TwoFAEnabled}}
                                <button type="button" class="btn danger" onclick="disable2FA()">关闭 2FA</button>
                                {{else}}
                                <button type="button" class="btn" onclick="enable2FA()">开启 2FA</button>
                                {{end}}
                            </div>
                        </div>

                        <div class="grid-form" style="gap:16px;margin-top:10px;grid-column:1/-1;grid-template-columns: 1fr 1fr 1fr;">
                            <div class="form-group"><label>面板域名</label><input name="master_domain" value="{{.MasterDomain}}"></div>
                            <div class="form-group"><label>面板 IP (IPv4)</label><input name="master_ip" value="{{.MasterIP}}"></div>
                            <div class="form-group"><label>面板 IP (IPv6)</label><input name="master_ipv6" value="{{.MasterIPv6}}"></div>
                        </div>

                        <div style="display:flex;gap:16px;margin-top:16px;border-top:1px solid var(--border);padding-top:24px;grid-column:1/-1">
                            <button class="btn" style="flex:2;height:48px"><i class="ri-save-3-line"></i> 保存系统配置</button>
                            <a href="/download_config" class="btn secondary" style="flex:1;height:48px" title="备份数据库"><i class="ri-download-cloud-2-line"></i> 备份</a>
                            <button type="button" class="btn warning" style="flex:1;height:48px" onclick="restartService()" title="重启面板服务"><i class="ri-restart-line"></i> 重启</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="mobile-nav">
    <div class="nav-btn active" onclick="nav('dashboard',this)"><i class="ri-dashboard-3-line"></i><span>概览</span></div>
    <div class="nav-btn" onclick="nav('rules',this)"><i class="ri-route-line"></i><span>规则</span></div>
    <div class="nav-btn" onclick="nav('deploy',this)"><i class="ri-rocket-2-line"></i><span>部署</span></div>
    <div class="nav-btn" onclick="nav('logs',this)"><i class="ri-file-list-3-line"></i><span>日志</span></div>
    <div class="nav-btn" onclick="nav('settings',this)"><i class="ri-settings-4-line"></i><span>设置</span></div>
</div>

<div id="editModal" class="modal">
    <div class="modal-content">
        <span class="close-modal" onclick="closeEdit()"><i class="ri-close-line"></i></span>
        <h3 style="margin-top:0;font-size:20px">修改转发规则</h3>
        <form action="/edit" method="POST">
            <input type="hidden" name="id" id="e_id">
            <div class="grid-form" style="grid-template-columns: 1fr 1fr; gap:24px">
                <div class="form-group"><label>分组名称</label><input name="group" id="e_group" placeholder="例如: 业务A"></div>
                <div class="form-group"><label>备注名称</label><input name="note" id="e_note"></div>
                <div class="form-group"><label>入口节点</label><select name="entry_agent" id="e_entry">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group"><label>入口端口</label><input type="number" name="entry_port" id="e_eport"></div>
                <div class="form-group"><label>出口节点</label><select name="exit_agent" id="e_exit">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group" style="grid-column: 1/-1"><label>目标地址 (IP/域名)</label><input name="target_ip" id="e_tip"></div>
                <div class="form-group"><label>目标端口</label><input type="number" name="target_port" id="e_tport"></div>
                <div class="form-group"><label>协议</label><select name="protocol" id="e_proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select></div>
                <div class="form-group"><label>流量限额 (GB)</label><input type="number" step="0.1" name="traffic_limit" id="e_limit"></div>
                <div class="form-group"><label>带宽限速 (MB/s)</label><input type="number" step="0.1" name="speed_limit" id="e_speed"></div>
                <div class="form-group" style="grid-column: 1/-1;margin-top:16px"><button class="btn" style="width:100%;height:48px">保存修改</button></div>
            </div>
        </form>
    </div>
</div>

<div id="confirmModal" class="modal">
    <div class="modal-content" style="max-width:400px;text-align:center;padding:40px 30px">
        <div style="font-size:56px;margin-bottom:20px;line-height:1" id="c_icon">⚠️</div>
        <h3 style="justify-content:center;margin-bottom:12px;font-size:20px" id="c_title">确认操作</h3>
        <p style="color:var(--text-sub);margin-bottom:32px;line-height:1.6" id="c_msg"></p>
        <div style="display:flex;gap:12px">
            <button class="btn secondary" style="flex:1" onclick="closeConfirm()">取消</button>
            <button id="c_btn" class="btn danger" style="flex:1">确认</button>
        </div>
    </div>
</div>

<div id="twoFAModal" class="modal">
    <div class="modal-content" style="text-align:center;max-width:360px">
        <span class="close-modal" onclick="document.getElementById('twoFAModal').style.display='none'"><i class="ri-close-line"></i></span>
        <h3 style="justify-content:center">绑定 2FA</h3>
        <p style="font-size:13px;color:var(--text-sub);margin-bottom:20px">请使用 Google Authenticator 扫描下方二维码</p>
        <div style="background:#fff;padding:10px;border-radius:12px;display:inline-block;margin-bottom:20px">
            <img id="qrImage" style="width:180px;height:180px;display:block">
        </div>
        <input id="twoFACode" placeholder="输入 6 位验证码" style="text-align:center;letter-spacing:6px;font-size:20px;margin-bottom:20px;font-family:'JetBrains Mono'">
        <button class="btn" onclick="verify2FA()" style="width:100%">验证并开启</button>
    </div>
</div>

<script>
    var m_domain="{{.MasterDomain}}", m_v4="{{.MasterIP}}", m_v6="{{.MasterIPv6}}", token="{{.Token}}", dwUrl="{{.DownloadURL}}", is_tls={{.IsTLS}};

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

    // 分组折叠功能
    document.addEventListener('DOMContentLoaded', () => {
        const collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        collapsed.forEach(g => {
            const header = document.querySelector('.group-header[data-group="'+g+'"]');
            if(header) setGroupState(header, false); 
        });
    });

    function toggleGroup(header) {
        const isCurrentlyCollapsed = header.classList.contains('group-collapsed');
        // 当前是折叠状态 -> 点击展开 (true)
        // 当前是展开状态 -> 点击折叠 (false)
        setGroupState(header, isCurrentlyCollapsed); 
        
        const group = header.getAttribute('data-group');
        let collapsed = JSON.parse(localStorage.getItem('collapsed_groups') || '[]');
        if (isCurrentlyCollapsed) { 
            // 展开了，从已折叠列表中移除
            collapsed = collapsed.filter(i => i !== group);
        } else {
            // 折叠了，加入列表
            if(!collapsed.includes(group)) collapsed.push(group);
        }
        localStorage.setItem('collapsed_groups', JSON.stringify(collapsed));
    }

    function setGroupState(header, expand) {
        const group = header.getAttribute('data-group');
        const rows = Array.from(document.querySelectorAll('.rule-row')).filter(row => row.getAttribute('data-group') === group);

        if (!expand) {
            header.classList.add('group-collapsed');
            rows.forEach(r => r.style.display = 'none');
        } else {
            header.classList.remove('group-collapsed');
            rows.forEach(r => r.style.display = 'table-row');
        }
    }

    function copyText(txt) {
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(txt).then(() => showToast("已复制: "+txt, "success"));
        else {
            const ta = document.createElement("textarea"); ta.value = txt; ta.style.position="fixed"; ta.style.left="-9999px";
            document.body.appendChild(ta); ta.focus(); ta.select();
            try { document.execCommand('copy'); showToast("已复制", "success"); } catch(e) { showToast("复制失败", "warn"); }
            document.body.removeChild(ta);
        }
    }

    function restartService() {
        showConfirm("重启服务", "确定要重启面板服务吗？<br>短暂的连接中断不会影响已建立的转发连接。", "warning", () => {
            fetch('/restart', {method: 'POST'}).then(() => {
                showToast("系统正在重启...", "warn");
                setTimeout(() => location.reload(), 3000);
            }).catch(() => {
                showToast("请求发送失败", "warn");
            });
        });
    }

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
        setTimeout(() => box.className = 'toast', 3000);
    }

    function showConfirm(title, msg, type, cb) {
        document.getElementById('c_title').innerText = title;
        document.getElementById('c_msg').innerHTML = msg;
        const btn = document.getElementById('c_btn');
        const icon = document.getElementById('c_icon');
        if(type === 'danger') { btn.className = 'btn danger'; btn.innerText = '确认删除'; icon.innerText = '🗑️'; } 
        else if(type === 'warning') { btn.className = 'btn warning'; btn.innerText = '确认重启'; icon.innerText = '🔄'; }
        else { btn.className = 'btn'; btn.innerText = '确认执行'; icon.innerText = '🤔'; }
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
        showToast("安装命令已生成 (" + arch + ")", "success");
    }
    function copyCmd() { copyText(document.getElementById('cmdText').innerText); }

    function delRule(id) { showConfirm("删除规则", "删除后该端口将立即停止服务，且无法恢复，确定吗？", "danger", () => location.href="/delete?id="+id); }
    function toggleRule(id) { location.href="/toggle?id="+id; }
    function resetTraffic(id) { showConfirm("重置流量", "确定要清零该规则的历史流量统计数据吗？", "normal", () => location.href="/reset_traffic?id="+id); }
    function delAgent(name) { showConfirm("卸载节点", "确定要卸载节点 <b>"+name+"</b> 吗？<br>系统将向该节点发送自毁指令。", "danger", () => location.href="/delete_agent?name="+name); }

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
    function verify2FA() { fetch('/2fa/verify', {method:'POST', body:JSON.stringify({secret:tempSecret, code:document.getElementById('twoFACode').value})}).then(r=>r.json()).then(d => { if(d.success) { showToast("2FA 已成功开启", "success"); setTimeout(()=>location.reload(), 1000); } else showToast("验证码错误", "warn"); }); }
    function disable2FA() { showConfirm("关闭 2FA", "关闭后账户安全性将降低，确定吗？", "danger", () => { fetch('/2fa/disable').then(r=>r.json()).then(d => { if(d.success) location.reload(); }); }); }

    // Chart.js Configuration
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = '#94a3b8';
    
    var ctx = document.getElementById('trafficChart').getContext('2d');
    var txGrad = ctx.createLinearGradient(0, 0, 0, 350);
    txGrad.addColorStop(0, 'rgba(129, 140, 248, 0.4)');
    txGrad.addColorStop(1, 'rgba(129, 140, 248, 0)');
    
    var rxGrad = ctx.createLinearGradient(0, 0, 0, 350);
    rxGrad.addColorStop(0, 'rgba(6, 182, 212, 0.4)');
    rxGrad.addColorStop(1, 'rgba(6, 182, 212, 0)');

    var chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [
                { label: '上传 (Tx)', data: Array(30).fill(0), borderColor: '#818cf8', backgroundColor: txGrad, borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 },
                { label: '下载 (Rx)', data: Array(30).fill(0), borderColor: '#06b6d4', backgroundColor: rxGrad, borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: true, labels: { boxWidth: 10, usePointStyle: true, font: {size: 11} } }, tooltip: { mode: 'index', intersect: false, backgroundColor: 'rgba(30, 41, 59, 0.9)', titleColor: '#f1f5f9', bodyColor: '#cbd5e1', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1 } },
            scales: {
                x: { display: false },
                y: { beginAtZero: true, grid: { color: 'rgba(128, 128, 128, 0.06)', borderDash: [4, 4] }, ticks: { callback: v => formatBytes(v)+'/s', font: {size: 10} } }
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
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true, padding: 20, font: {size: 11} } } },
            cutout: '70%'
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
        if(b<=0) return "无限制";
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
                        
                        d.rules.forEach(r => {
                            const traf = document.getElementById('rule-traffic-'+r.id); if(traf) traf.innerText = formatBytes(r.total);
                            const uc = document.getElementById('rule-uc-'+r.id); if(uc) uc.innerText = r.uc;
                            const lat = document.getElementById('rule-latency-'+r.id);
                            const dot = document.getElementById('rule-status-dot-'+r.id);
                            if(lat && dot) {
                                if(r.status) {
                                    lat.innerHTML = '<i class="ri-pulse-line" style="color:#10b981"></i> ' + r.latency + ' ms';
                                    dot.parentElement.className = 'badge success'; dot.parentElement.innerHTML = '<span class="status-dot pulse"></span> 运行中';
                                } else {
                                    lat.innerHTML = '<i class="ri-error-warning-fill" style="color:#ef4444"></i> 离线';
                                    dot.parentElement.className = 'badge danger'; dot.parentElement.innerHTML = '<span class="status-dot"></span> 异常';
                                }
                            }
                            if(r.limit > 0) {
                                let pct = (r.total / r.limit) * 100; if(pct > 100) pct = 100;
                                const bar = document.getElementById('rule-bar-'+r.id);
                                if(bar) { bar.style.width = pct + '%'; bar.style.background = pct > 90 ? '#ef4444' : '#818cf8'; }
                                const txt = document.getElementById('rule-limit-text-'+r.id);
                                if(txt) txt.innerText = '已用 ' + pct.toFixed(1) + '%';
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
                            html += '<tr><td style="font-family:\'JetBrains Mono\';color:var(--text-sub)">'+l.time+'</td>'+
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
