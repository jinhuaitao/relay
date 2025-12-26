package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
)

// --- 配置与常量 ---

const (
	ConfigFile  = "config.json"
	ControlPort = ":9999"
	WebPort     = ":8888"
	DownloadURL = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"

	// --- 性能调优参数 ---
	TCPKeepAlive   = 60 * time.Second
	UDPBufferSize  = 4 * 1024 * 1024
	CopyBufferSize = 32 * 1024
	MaxLogEntries  = 200
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
	MasterIP     string        `json:"master_ip"`
	MasterIPv6   string        `json:"master_ipv6"`
	MasterDomain string        `json:"master_domain"`
	IsSetup      bool          `json:"is_setup"`
	TgBotToken   string        `json:"tg_bot_token"`
	TgChatID     string        `json:"tg_chat_id"`
	
	TwoFAEnabled bool   `json:"two_fa_enabled"`
	TwoFASecret  string `json:"two_fa_secret"`

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
	config           AppConfig
	agents           = make(map[string]*AgentInfo)
	rules            = make([]LogicalRule, 0)
	opLogs           = make([]OpLog, 0)
	mu               sync.Mutex
	runningListeners sync.Map
	
	activeTasks      sync.Map 
	activeTargets    sync.Map 
	
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
	
	// TLS 状态
	isMasterTLS bool = false
	useTLS      bool = false
)

// --- 密码安全工具函数 ---

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
		log.Printf("IP %s 因多次登录失败被封禁15分钟", ip)
	}
}

// --- 主程序 ---

func main() {
	setRLimit()

	mode := flag.String("mode", "master", "运行模式")
	name := flag.String("name", "", "Agent名称")
	connect := flag.String("connect", "", "Master地址")
	token := flag.String("token", "", "通信Token")
	serviceOp := flag.String("service", "", "install | uninstall")
	tlsFlag := flag.Bool("tls", false, "使用 TLS 加密连接 (Agent模式)")

	flag.Parse()

	if *serviceOp != "" {
		handleService(*serviceOp, *mode, *name, *connect, *token, *tlsFlag)
		return
	}

	setupSignalHandler()

	if *mode == "master" {
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
	entry := OpLog{Time: time.Now().Format("01-02 15:04:05"), IP: ip, Action: action, Msg: msg}
	mu.Lock()
	opLogs = append([]OpLog{entry}, opLogs...)
	if len(opLogs) > MaxLogEntries {
		opLogs = opLogs[:MaxLogEntries]
	}
	atomic.StoreInt32(&configDirty, 1)
	mu.Unlock()
}

func addSystemLog(ip, action, msg string) {
	entry := OpLog{Time: time.Now().Format("01-02 15:04:05"), IP: ip, Action: action, Msg: msg}
	mu.Lock()
	opLogs = append([]OpLog{entry}, opLogs...)
	if len(opLogs) > MaxLogEntries {
		opLogs = opLogs[:MaxLogEntries]
	}
	atomic.StoreInt32(&configDirty, 1)
	mu.Unlock()
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
	log.Println("开始执行自毁程序...")
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
	if config.TgBotToken == "" || config.TgChatID == "" {
		return
	}
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.TgBotToken)
	data := url.Values{}
	data.Set("chat_id", config.TgChatID)
	data.Set("text", text)
	go func() { http.PostForm(api, data) }()
}

// ================= MASTER =================

func runMaster() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			if atomic.CompareAndSwapInt32(&configDirty, 1, 0) {
				mu.Lock()
				saveConfig()
				mu.Unlock()
			}
		}
	}()

	go broadcastLoop()

	go func() {
		// 自动检测 TLS 证书
		var ln net.Listener
		var err error
		
		if _, errStat := os.Stat("server.crt"); errStat == nil {
			if _, errStat := os.Stat("server.key"); errStat == nil {
				cert, errLoad := tls.LoadX509KeyPair("server.crt", "server.key")
				if errLoad == nil {
					tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
					ln, err = tls.Listen("tcp", ControlPort, tlsConfig)
					if err == nil {
						log.Println("🔐 Master 已启用 TLS 加密模式 (端口:9999)")
						isMasterTLS = true // 标记开启
					}
				}
			}
		}

		if ln == nil {
			ln, err = net.Listen("tcp", ControlPort)
			if err != nil {
				log.Fatal(err)
			}
			log.Println("⚠️ Master 正在使用明文 TCP 模式")
		}

		for {
			c, err := ln.Accept()
			if err == nil {
				go handleAgentConn(c)
			}
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
	// 2FA API
	http.HandleFunc("/2fa/generate", authMiddleware(handle2FAGenerate))
	http.HandleFunc("/2fa/verify", authMiddleware(handle2FAVerify))
	http.HandleFunc("/2fa/disable", authMiddleware(handle2FADisable))

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
		var logData []OpLog
		
		if len(opLogs) > 0 {
			limit := 15
			if len(opLogs) < limit {
				limit = len(opLogs)
			}
			logData = make([]OpLog, limit)
			copy(logData, opLogs[:limit])
		}

		for _, a := range agents {
			agentData = append(agentData, AgentStatusData{Name: a.Name, SysStatus: a.SysStatus})
		}
		for _, r := range rules {
			currentTx += r.TotalTx
			currentRx += r.TotalRx
			
			ruleData = append(ruleData, RuleStatusData{
				ID:        r.ID,
				Name:      r.Note, // For chart label
				Total:     r.TotalTx + r.TotalRx,
				UserCount: r.UserCount,
				Limit:     r.TrafficLimit,
				Status:    r.TargetStatus,
				Latency:   r.TargetLatency,
			})
		}
		mu.Unlock()

		var speedTx int64 = 0
		var speedRx int64 = 0
		
		// Initial skip
		if lastTotalTx != 0 || lastTotalRx != 0 {
			speedTx = currentTx - lastTotalTx
			speedRx = currentRx - lastTotalRx
		}
		if speedTx < 0 { speedTx = 0 }
		if speedRx < 0 { speedRx = 0 }
		
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
	if dec.Decode(&msg) != nil || msg.Type != "auth" {
		return
	}
	data, ok := msg.Payload.(map[string]interface{})
	if !ok || data["token"].(string) != config.AgentToken {
		return
	}
	name := data["name"].(string)
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	mu.Lock()
	if old, exists := agents[name]; exists {
		old.Conn.Close()
	}
	agents[name] = &AgentInfo{Name: name, RemoteIP: remoteIP, Conn: conn}
	mu.Unlock()

	log.Printf("Agent上线: %s (%s)", name, remoteIP)
	addSystemLog(remoteIP, "Agent 上线", fmt.Sprintf("节点 %s 已连接", name))
	sendTelegram(fmt.Sprintf("🟢 节点上线通知\n名称: %s\nIP: %s\n时间: %s", name, remoteIP, time.Now().Format("15:04:05")))

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
		if m.Type == "uninstalling" {
			log.Printf("Agent [%s] 正在卸载...", name)
			addSystemLog(remoteIP, "Agent 卸载", fmt.Sprintf("节点 %s 正在执行自毁", name))
		}
	}
	mu.Lock()
	if curr, ok := agents[name]; ok && curr.Conn == conn {
		delete(agents, name)
		mu.Unlock()
		log.Printf("Agent下线: %s", name)
		addSystemLog(remoteIP, "Agent 下线", fmt.Sprintf("节点 %s 连接断开", name))
		sendTelegram(fmt.Sprintf("🔴 节点下线通知\n名称: %s\n时间: %s", name, time.Now().Format("15:04:05")))
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
		saveConfig()
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
					if rep.Latency >= 0 {
						rules[i].TargetStatus = true
						rules[i].TargetLatency = rep.Latency
					} else {
						rules[i].TargetStatus = false
						rules[i].TargetLatency = 0
					}
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
			ID: r.ID + "_exit", 
			Protocol: r.Protocol, 
			Listen: ":" + r.BridgePort, 
			Target: finalTargetStr, 
			SpeedLimit: r.SpeedLimit, 
		})

		if exit, ok := agents[r.ExitAgent]; ok {
			rip := exit.RemoteIP
			if strings.Contains(rip, ":") && !strings.Contains(rip, "[") {
				rip = "[" + rip + "]"
			}
			tasksMap[r.EntryAgent] = append(tasksMap[r.EntryAgent], ForwardTask{
				ID: r.ID + "_entry", 
				Protocol: r.Protocol, 
				Listen: ":" + r.EntryPort, 
				Target: fmt.Sprintf("%s:%s", rip, r.BridgePort),
				SpeedLimit: r.SpeedLimit,
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
	w.Header().Set("Cache-Control", "no-cache")
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
	
	displayLogs := make([]OpLog, len(opLogs))
	copy(displayLogs, opLogs)
	
	twoFA := config.TwoFAEnabled
	mu.Unlock()

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
	}{al, displayRules, displayLogs, config.AgentToken, config.WebUser, DownloadURL, totalTraffic, config.MasterIP, config.MasterIPv6, config.MasterDomain, config, twoFA, isMasterTLS}

	t := template.New("dash").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"add":         func(a, b int64) int64 { return a + b },
		"percent": func(currTx, currRx, limit int64) float64 {
			if limit <= 0 { return 0 }
			p := (float64(currTx+currRx) / float64(limit)) * 100
			if p > 100 { p = 100 }
			return p
		},
		"formatSpeed": func(bytesPerSec int64) string {
			if bytesPerSec <= 0 { return "无限制" }
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
		saveConfig()
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
		http.Error(w, "尝试次数过多，请稍后再试", 429)
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
		salt := parts[0]
		hash := parts[1]
		if r.FormValue("username") == u && hashPassword(r.FormValue("password"), salt) == hash {
			passMatch = true
		}
	} else {
		if r.FormValue("username") == u && md5Hash(r.FormValue("password")) == storedVal {
			passMatch = true
			newSalt := generateSalt()
			newHash := hashPassword(r.FormValue("password"), newSalt)
			mu.Lock()
			config.WebPass = newSalt + "$" + newHash
			saveConfig()
			mu.Unlock()
		}
	}

	if !passMatch {
		recordLoginFail(ip)
		t, _ := template.New("l").Parse(loginHtml)
		t.Execute(w, map[string]interface{}{"TwoFA": false, "Error": "账号或密码错误"})
		return
	}

	if twoFAEnabled {
		code := r.FormValue("code")
		if code == "" || !totp.Validate(code, twoFASecret) {
			recordLoginFail(ip)
			t, _ := template.New("l").Parse(loginHtml)
			t.Execute(w, map[string]interface{}{"TwoFA": true, "Error": "两步验证码错误"})
			return
		}
	}

	sid := make([]byte, 16)
	rand.Read(sid)
	sidStr := hex.EncodeToString(sid)
	mu.Lock()
	sessions[sidStr] = time.Now().Add(12 * time.Hour)
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	addLog(r, "登录成功", "管理员登录面板")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	addLog(r, "退出登录", "管理员退出面板")
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handle2FAGenerate(w http.ResponseWriter, r *http.Request) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoRelay-Pro",
		AccountName: config.WebUser,
	})
	if err != nil {
		http.Error(w, "生成失败", 500)
		return
	}

	var buf bytes.Buffer
	img, _ := qr.Encode(key.URL(), qr.M, qr.Auto)
	img, _ = barcode.Scale(img, 200, 200)
	png.Encode(&buf, img)
	
	resp := map[string]string{
		"secret": key.Secret(),
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	}
	json.NewEncoder(w).Encode(resp)
}

func handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if totp.Validate(req.Code, req.Secret) {
		mu.Lock()
		config.TwoFASecret = req.Secret
		config.TwoFAEnabled = true
		saveConfig()
		mu.Unlock()
		addLog(r, "安全设置", "开启双因素认证 (2FA)")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{"success": false})
	}
}

func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	config.TwoFAEnabled = false
	config.TwoFASecret = ""
	saveConfig()
	mu.Unlock()
	addLog(r, "安全设置", "关闭双因素认证 (2FA)")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// --- 原有 Handlers ---

func handleAddRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)
	
	mu.Lock()
	newRule := LogicalRule{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Note:         r.FormValue("note"),
		EntryAgent:   r.FormValue("entry_agent"),
		EntryPort:    r.FormValue("entry_port"),
		ExitAgent:    r.FormValue("exit_agent"),
		TargetIP:     r.FormValue("target_ip"),
		TargetPort:   r.FormValue("target_port"),
		Protocol:     r.FormValue("protocol"),
		TrafficLimit: int64(limitGB * 1024 * 1024 * 1024),
		SpeedLimit:   int64(speedMB * 1024 * 1024),
		BridgePort:   fmt.Sprintf("%d", 20000+time.Now().UnixNano()%30000),
		Disabled:     false,
	}
	rules = append(rules, newRule)
	saveConfig()
	mu.Unlock()
	addLog(r, "新建规则", fmt.Sprintf("添加转发: %s -> %s:%s", newRule.Note, newRule.TargetIP, newRule.TargetPort))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleEditRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	id := r.FormValue("id")
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)

	mu.Lock()
	found := false
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Note = r.FormValue("note")
			rules[i].EntryAgent = r.FormValue("entry_agent")
			rules[i].EntryPort = r.FormValue("entry_port")
			rules[i].ExitAgent = r.FormValue("exit_agent")
			rules[i].TargetIP = r.FormValue("target_ip")
			rules[i].TargetPort = r.FormValue("target_port")
			rules[i].Protocol = r.FormValue("protocol")
			rules[i].TrafficLimit = int64(limitGB * 1024 * 1024 * 1024)
			rules[i].SpeedLimit = int64(speedMB * 1024 * 1024)
			found = true
			break
		}
	}
	if found {
		saveConfig()
	}
	mu.Unlock()
	if found {
		addLog(r, "修改规则", fmt.Sprintf("更新规则 ID: %s", id))
		go pushConfigToAll()
	}
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleToggleRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	found := false
	state := ""
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Disabled = !rules[i].Disabled
			found = true
			if rules[i].Disabled { state = "暂停" } else { state = "启用" }
			break
		}
	}
	if found {
		saveConfig()
	}
	mu.Unlock()
	if found {
		addLog(r, "切换状态", fmt.Sprintf("%s 规则 ID: %s", state, id))
		go pushConfigToAll()
	}
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleResetTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	found := false
	for i := range rules {
		if rules[i].ID == id {
			rules[i].TotalTx = 0
			rules[i].TotalRx = 0
			found = true
			break
		}
	}
	if found {
		saveConfig()
	}
	mu.Unlock()
	if found {
		addLog(r, "重置流量", fmt.Sprintf("重置规则 ID: %s 流量统计", id))
		go pushConfigToAll()
	}
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
	saveConfig()
	mu.Unlock()
	addLog(r, "删除规则", fmt.Sprintf("移除规则 ID: %s", id))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	if agent, ok := agents[name]; ok {
		go func(c net.Conn) {
			json.NewEncoder(c).Encode(Message{Type: "uninstall"})
		}(agent.Conn)
	}
	mu.Unlock()
	addLog(r, "卸载节点", fmt.Sprintf("发送卸载指令给: %s", name))
	sendTelegram(fmt.Sprintf("🗑️ 节点删除指令已发送\n目标: %s\n正在等待节点响应...", name))
	http.Redirect(w, r, "/#dashboard", http.StatusSeeOther)
}

func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	mu.Lock()
	if p := r.FormValue("password"); p != "" {
		salt := generateSalt()
		config.WebPass = salt + "$" + hashPassword(p, salt)
	}
	if t := r.FormValue("token"); t != "" {
		config.AgentToken = t
	}
	config.MasterIP = r.FormValue("master_ip")
	config.MasterIPv6 = r.FormValue("master_ipv6")
	config.MasterDomain = r.FormValue("master_domain")
	config.TgBotToken = r.FormValue("tg_bot_token")
	config.TgChatID = r.FormValue("tg_chat_id")
	saveConfig()
	mu.Unlock()
	addLog(r, "系统设置", "更新系统配置参数")
	http.Redirect(w, r, "/#settings", http.StatusSeeOther)
}

func handleDownloadConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=config.json")
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, ConfigFile)
	addLog(r, "数据备份", "下载配置文件 config.json")
}

func handleExportLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	b, _ := json.MarshalIndent(opLogs, "", "  ")
	mu.Unlock()
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
	addLog(r, "日志导出", "导出系统操作日志")
}

// ================= AGENT CORE =================

func runAgent(name, masterAddr, token string) {
	for {
		// 自动探测 TLS
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
			// *** 关键优化：将心跳同步为 1 秒 ***
			t := time.NewTicker(1 * time.Second)
			h := time.NewTicker(10 * time.Second) // 健康检查 10s
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
						conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
						json.NewEncoder(conn).Encode(Message{Type: "stats", Payload: reps})
						conn.SetWriteDeadline(time.Time{})
					} else {
						status := getSysStatus()
						json.NewEncoder(conn).Encode(Message{Type: "ping", Payload: status})
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
				log.Println("收到卸载指令，正在执行自毁程序...")
				json.NewEncoder(conn).Encode(Message{Type: "uninstalling"})
				time.Sleep(200 * time.Millisecond)
				close(stop)
				conn.Close()
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
					restart := false
					if oldTaskVal, loaded := activeTasks.Load(t.ID); loaded {
						oldTask := oldTaskVal.(ForwardTask)
						if oldTask.Target != t.Target || oldTask.SpeedLimit != t.SpeedLimit {
							restart = true
						}
					} else {
						restart = true
					}

					if restart {
						if closeFunc, ok := runningListeners.Load(t.ID); ok {
							closeFunc.(func())()
							runningListeners.Delete(t.ID)
							agentTraffic.Delete(t.ID)
							agentUserCounts.Delete(t.ID)
							if oldTaskVal, loaded := activeTasks.Load(t.ID); loaded {
								oldTargets := strings.Split(oldTaskVal.(ForwardTask).Target, ",")
								for _, ot := range oldTargets {
									targetHealthMap.Delete(strings.TrimSpace(ot))
								}
							}
							activeTasks.Delete(t.ID)
							activeTargets.Delete(t.ID)
							time.Sleep(200 * time.Millisecond)
						}
						
						agentTraffic.Store(t.ID, &TrafficCounter{})
						var uz int64 = 0
						agentUserCounts.Store(t.ID, &uz)
						activeTargets.Store(t.ID, t.Target)
						activeTasks.Store(t.ID, t)
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
		targetsStr := value.(string)
		targets := strings.Split(targetsStr, ",")
		var bestLat int64 = -1
		
		for _, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" { continue }
			
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
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		json.NewEncoder(conn).Encode(Message{Type: "health", Payload: results})
		conn.SetWriteDeadline(time.Time{})
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
				runningListeners.Delete(t.ID)
				activeTargets.Delete(t.ID)
				activeTasks.Delete(t.ID)
				agentTraffic.Delete(t.ID)
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
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetKeepAlive(true)
					tc.SetKeepAlivePeriod(TCPKeepAlive)
					tc.SetNoDelay(true)
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
					pipeTCP(conn, t.Target, t.ID, t.SpeedLimit)
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
				runningListeners.Delete(t.ID)
				activeTargets.Delete(t.ID)
				activeTasks.Delete(t.ID)
				agentTraffic.Delete(t.ID)
				return
			}
			ln.SetReadBuffer(UDPBufferSize)
			ln.SetWriteBuffer(UDPBufferSize)
			l.Lock()
			closers = append(closers, func() { ln.Close() })
			l.Unlock()
			handleUDP(ln, t.Target, t.ID, ipTracker, t.SpeedLimit)
		}()
	}
}

func pipeTCP(src net.Conn, targetStr, tid string, limit int64) {
	defer src.Close()
	allTargets := strings.Split(targetStr, ",")
	
	var healthyTargets []string
	for _, t := range allTargets {
		t = strings.TrimSpace(t)
		if t == "" { continue }
		if status, ok := targetHealthMap.Load(t); ok && status.(bool) {
			healthyTargets = append(healthyTargets, t)
		}
	}

	candidates := healthyTargets
	if len(candidates) == 0 {
		candidates = []string{}
		for _, t := range allTargets {
			if strings.TrimSpace(t) != "" { candidates = append(candidates, strings.TrimSpace(t)) }
		}
	}

	var dst net.Conn
	var err error
	if len(candidates) > 0 {
		startIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
		idx := int(startIdx.Int64())
		for i := 0; i < len(candidates); i++ {
			t := candidates[(idx+i)%len(candidates)]
			dst, err = net.DialTimeout("tcp", t, 2*time.Second)
			if err == nil {
				break
			}
		}
	}

	if dst == nil {
		return
	}
	defer dst.Close()
	
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(TCPKeepAlive)
		tc.SetNoDelay(true)
	}
	v, _ := agentTraffic.Load(tid)
	if v == nil {
		return
	}
	cnt := v.(*TrafficCounter)
	
	go copyCount(dst, src, &cnt.Tx, limit)
	copyCount(src, dst, &cnt.Rx, limit)
}

func handleUDP(ln *net.UDPConn, targetStr string, tid string, tracker *IpTracker, limit int64) {
	targets := strings.Split(targetStr, ",")
	
	udpSessions := &sync.Map{}
	defer func() {
		udpSessions.Range(func(key, value interface{}) bool {
			value.(*udpSession).conn.Close()
			return true
		})
	}()
	
	v, _ := agentTraffic.Load(tid)
	if v == nil {
		return
	}
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
			throttle(n, limit, time.Now()) 
		} else {
			var candidates []string
			for _, t := range targets {
				t = strings.TrimSpace(t)
				if t == "" { continue }
				if status, ok := targetHealthMap.Load(t); ok && status.(bool) {
					candidates = append(candidates, t)
				}
			}
			if len(candidates) == 0 {
				for _, t := range targets {
					if strings.TrimSpace(t) != "" { candidates = append(candidates, strings.TrimSpace(t)) }
				}
			}
			if len(candidates) == 0 { continue }

			randIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
			t := candidates[randIdx.Int64()]
			dstAddr, _ := net.ResolveUDPAddr("udp", t)
			if dstAddr == nil { continue }

			newConn, err := net.DialUDP("udp", nil, dstAddr)
			if err != nil {
				continue
			}
			s := &udpSession{conn: newConn, lastActive: time.Now()}
			udpSessions.Store(sAddr, s)
			tracker.Add(sAddr)
			
			newConn.Write(buf[:n])
			throttle(n, limit, time.Now()) 

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
					throttle(m, limit, time.Now())
				}
			}(newConn, srcAddr, sAddr)
		}
	}
}

func throttle(n int, limit int64, start time.Time) {
	if limit > 0 {
		expectedDuration := time.Duration(1e9 * int64(n) / limit)
		actualDuration := time.Since(start)
		if expectedDuration > actualDuration {
			time.Sleep(expectedDuration - actualDuration)
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
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				atomic.AddInt64(c, int64(nw))
			}
			if ew != nil {
				break
			}
			if nr != nw {
				break
			}
			throttle(nr, limit, start)
		}
		if err != nil {
			break
		}
	}
}

type CounterWriter struct {
	io.Writer
	Counter *int64
}

func (w *CounterWriter) Write(p []byte) (n int, err error) {
	n, err = w.Writer.Write(p)
	if n > 0 {
		atomic.AddInt64(w.Counter, int64(n))
	}
	return
}

func loadConfig() {
	f, err := os.Open(ConfigFile)
	if err == nil {
		defer f.Close()
		json.NewDecoder(f).Decode(&config)
		rules = config.Rules
		opLogs = config.Logs
	}
}

func saveConfig() {
	config.Rules = rules
	config.Logs = opLogs
	f, _ := os.Create(ConfigFile)
	defer f.Close()
	json.NewEncoder(f).Encode(&config)
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() { <-c; os.Exit(0) }()
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
:root { --primary: #6366f1; --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --text-sub: #94a3b8; --border: #334155; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background-image: radial-gradient(circle at top right, #1e1b4b, transparent 40%), radial-gradient(circle at bottom left, #312e81, transparent 40%); }
.card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 40px; border-radius: 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); width: 100%; max-width: 400px; border: 1px solid rgba(255,255,255,0.1); }
h2 { text-align: center; margin: 0 0 10px 0; font-size: 24px; font-weight: 700; background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
p { text-align: center; color: var(--text-sub); margin-bottom: 30px; font-size: 14px; }
.input-group { margin-bottom: 20px; position: relative; }
.input-group i { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: var(--text-sub); }
input { width: 100%; padding: 14px 14px 14px 44px; border: 1px solid var(--border); border-radius: 12px; background: rgba(15, 23, 42, 0.6); color: var(--text); outline: none; transition: .3s; box-sizing: border-box; font-size: 14px; }
input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); background: rgba(15, 23, 42, 0.8); }
button { width: 100%; padding: 14px; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: .3s; box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.3); }
button:hover { transform: translateY(-2px); box-shadow: 0 20px 25px -5px rgba(99, 102, 241, 0.4); }
</style>
</head>
<body>
<form class="card" method="POST">
    <h2>GoRelay Pro</h2>
    <p>欢迎使用，请配置您的初始管理员账户</p>
    <div class="input-group"><i class="ri-user-line"></i><input name="username" placeholder="设置管理员用户名" required autocomplete="off"></div>
    <div class="input-group"><i class="ri-lock-password-line"></i><input type="password" name="password" placeholder="设置登录密码" required></div>
    <div class="input-group"><i class="ri-key-2-line"></i><input name="token" placeholder="设置通信 Token (用于连接 Agent)" required></div>
    <button>完成初始化 <i class="ri-arrow-right-line" style="vertical-align: middle; margin-left: 5px;"></i></button>
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
:root { --primary: #6366f1; --bg: #0f172a; --text: #f8fafc; --text-sub: #94a3b8; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; position: relative; }
.bg-glow { position: absolute; width: 600px; height: 600px; background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, rgba(0,0,0,0) 70%); top: -10%; left: -10%; z-index: -1; animation: float 10s infinite ease-in-out; }
.bg-glow-2 { position: absolute; width: 500px; height: 500px; background: radial-gradient(circle, rgba(168,85,247,0.15) 0%, rgba(0,0,0,0) 70%); bottom: -10%; right: -10%; z-index: -1; animation: float 10s infinite ease-in-out reverse; }
@keyframes float { 0%,100%{transform:translate(0,0)} 50%{transform:translate(30px, 30px)} }

.card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); padding: 48px 40px; border-radius: 24px; width: 100%; max-width: 380px; border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
.header { text-align: center; margin-bottom: 32px; }
.logo { font-size: 48px; margin-bottom: 10px; display: inline-block; background: linear-gradient(135deg, #818cf8, #c084fc); -webkit-background-clip: text; color: transparent; }
.header h2 { margin: 0; font-size: 24px; font-weight: 700; color: #fff; }
.header p { margin: 8px 0 0; color: var(--text-sub); font-size: 14px; }

.input-box { margin-bottom: 20px; position: relative; }
.input-box i { position: absolute; left: 16px; top: 15px; color: var(--text-sub); font-size: 18px; transition: .3s; }
input { width: 100%; padding: 14px 14px 14px 48px; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; font-size: 15px; outline: none; transition: .3s; box-sizing: border-box; }
input:focus { border-color: var(--primary); background: rgba(15, 23, 42, 0.8); box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.15); }
input:focus + i { color: var(--primary); }

button { width: 100%; padding: 14px; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: .3s; margin-top: 10px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); display: flex; align-items: center; justify-content: center; gap: 8px; }
button:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.4); }
.error-msg { background: rgba(239, 68, 68, 0.1); color: #ef4444; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 20px; text-align: center; border: 1px solid rgba(239, 68, 68, 0.2); display: flex; align-items: center; justify-content: center; gap: 6px; }
</style>
</head>
<body>
<div class="bg-glow"></div><div class="bg-glow-2"></div>
<form class="card" method="POST">
    <div class="header">
        <i class="ri-globe-line logo"></i>
        <h2>GoRelay Pro</h2>
        <p>安全内网穿透管理系统</p>
    </div>
    {{if .Error}}<div class="error-msg"><i class="ri-error-warning-line"></i> {{.Error}}</div>{{end}}
    
    <div class="input-box"><input name="username" placeholder="管理员账号" required><i class="ri-user-3-line"></i></div>
    <div class="input-box"><input type="password" name="password" placeholder="密码" required><i class="ri-lock-2-line"></i></div>
    {{if .TwoFA}}
    <div class="input-box"><input name="code" placeholder="两步验证码 (2FA)" required pattern="[0-9]{6}" maxlength="6" style="letter-spacing: 2px; text-align: center; padding-left: 14px;"><i class="ri-shield-keyhole-line" style="left: auto; right: 16px;"></i></div>
    {{end}}
    <button>登录系统 <i class="ri-arrow-right-line"></i></button>
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
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
/* --- 现代 CSS 变量 --- */
:root {
    --primary: #6366f1; --primary-hover: #4f46e5; --primary-light: rgba(99, 102, 241, 0.15);
    --bg-body: #f1f5f9; --bg-sidebar: #0f172a; --bg-card: #ffffff;
    --text-main: #0f172a; --text-sub: #64748b; --text-inv: #ffffff;
    --border: #e2e8f0; --input-bg: #f8fafc;
    --success: #10b981; --success-bg: #d1fae5; --success-text: #065f46;
    --danger: #ef4444; --danger-bg: #fee2e2; --danger-text: #991b1b;
    --warning: #f59e0b; --warning-bg: #fef3c7; --warning-text: #92400e;
    --radius: 16px;
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -1px rgba(0,0,0,0.03);
    --sidebar-w: 260px;
    --trans: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
[data-theme="dark"] {
    --bg-body: #020617; --bg-sidebar: #0f172a; --bg-card: #1e293b;
    --text-main: #f8fafc; --text-sub: #94a3b8;
    --border: #334155; --input-bg: #0f172a;
    --primary-light: rgba(99, 102, 241, 0.2);
    --success-bg: rgba(16, 185, 129, 0.2); --success-text: #34d399;
    --danger-bg: rgba(239, 68, 68, 0.2); --danger-text: #f87171;
    --warning-bg: rgba(245, 158, 11, 0.2); --warning-text: #fbbf24;
    --shadow: 0 10px 15px -3px rgba(0,0,0,0.4);
}

/* --- 基础样式 --- */
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body { margin: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg-body); color: var(--text-main); height: 100vh; display: flex; overflow: hidden; transition: var(--trans); }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-sub); }

/* --- 侧边栏 --- */
.sidebar { width: var(--sidebar-w); background: var(--bg-sidebar); color: var(--text-inv); display: flex; flex-direction: column; flex-shrink: 0; z-index: 50; border-right: 1px solid rgba(255,255,255,0.05); }
.brand { height: 70px; display: flex; align-items: center; padding: 0 24px; font-size: 20px; font-weight: 800; border-bottom: 1px solid rgba(255,255,255,0.05); gap: 10px; background: linear-gradient(90deg, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.brand i { color: #818cf8; font-size: 24px; -webkit-text-fill-color: #818cf8; }
.menu { flex: 1; padding: 20px 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; }
.item { display: flex; align-items: center; padding: 12px 16px; color: #94a3b8; cursor: pointer; border-radius: 12px; transition: var(--trans); font-size: 14px; font-weight: 500; }
.item:hover { background: rgba(255,255,255,0.05); color: #fff; }
.item.active { background: linear-gradient(90deg, var(--primary) 0%, rgba(99,102,241,0.8) 100%); color: #fff; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); }
.item i { margin-right: 12px; font-size: 18px; }

.user-panel { padding: 20px; border-top: 1px solid rgba(255,255,255,0.05); background: rgba(0,0,0,0.1); }
.user-card { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.avatar { width: 36px; height: 36px; background: linear-gradient(135deg, #a5b4fc, #6366f1); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: bold; font-size: 16px; }
.user-meta div:first-child { font-weight: 600; font-size: 14px; }
.user-meta div:last-child { font-size: 12px; opacity: 0.6; }
.btn-logout { display: flex; align-items: center; justify-content: center; width: 100%; padding: 8px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); background: transparent; color: #f87171; cursor: pointer; font-size: 12px; gap: 6px; transition: var(--trans); text-decoration: none; }
.btn-logout:hover { background: rgba(239,68,68,0.1); border-color: #ef4444; }

/* --- 主内容区 --- */
.main { flex: 1; display: flex; flex-direction: column; position: relative; width: 100%; }
.header { height: 70px; background: var(--bg-card); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 24px; transition: var(--trans); }
.page-title { font-weight: 700; font-size: 18px; display: flex; align-items: center; gap: 10px; }
.theme-toggle { width: 40px; height: 40px; border-radius: 50%; border: 1px solid var(--border); background: var(--bg-body); color: var(--text-main); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: var(--trans); }
.theme-toggle:hover { background: var(--border); }

.content { flex: 1; padding: 24px; overflow-y: auto; overflow-x: hidden; }
.page { display: none; animation: fadeIn 0.4s ease; max-width: 1400px; margin: 0 auto; }
.page.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

/* --- 卡片与布局 --- */
.card { background: var(--bg-card); padding: 24px; border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 24px; position: relative; overflow: hidden; }
h3 { margin: 0 0 20px 0; font-size: 16px; color: var(--text-main); font-weight: 700; display: flex; align-items: center; gap: 8px; }
h3 i { color: var(--primary); }

.dashboard-grid { display: grid; grid-template-columns: 2.5fr 1fr; gap: 24px; margin-bottom: 24px; }
@media (max-width: 1024px) { .dashboard-grid { grid-template-columns: 1fr; } }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 24px; }
.stat-item { padding: 24px; display: flex; align-items: center; justify-content: space-between; position: relative; overflow: hidden; }
.stat-item::after { content: ''; position: absolute; right: -20px; top: -20px; width: 100px; height: 100px; background: var(--primary); opacity: 0.05; border-radius: 50%; filter: blur(20px); }
.stat-val { font-size: 28px; font-weight: 800; color: var(--text-main); line-height: 1.2; letter-spacing: -0.5px; }
.stat-label { color: var(--text-sub); font-size: 13px; font-weight: 500; margin-top: 4px; }
.stat-icon { width: 52px; height: 52px; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 26px; background: var(--input-bg); color: var(--primary); border: 1px solid var(--border); }

/* --- 表格 --- */
.table-container { overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); background: var(--bg-card); }
table { width: 100%; border-collapse: collapse; white-space: nowrap; }
th { text-align: left; padding: 16px 24px; color: var(--text-sub); font-size: 12px; font-weight: 600; text-transform: uppercase; background: var(--input-bg); border-bottom: 1px solid var(--border); }
td { padding: 16px 24px; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--text-main); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--input-bg); }

.badge { padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
.badge.success { background: var(--success-bg); color: var(--success-text); }
.badge.danger { background: var(--danger-bg); color: var(--danger-text); }
.badge.warning { background: var(--warning-bg); color: var(--warning-text); }
.status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; position: relative; }
.status-dot.pulse::after { content: ''; position: absolute; width: 100%; height: 100%; border-radius: 50%; background: inherit; animation: pulse 1.5s infinite; opacity: 0.6; transform: scale(1); }
@keyframes pulse { 0% { transform: scale(1); opacity: 0.6; } 100% { transform: scale(2.5); opacity: 0; } }

/* --- 按钮与表单 --- */
.grid-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; align-items: end; }
.form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; color: var(--text-sub); }
input, select { width: 100%; padding: 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--input-bg); color: var(--text-main); font-size: 14px; outline: none; transition: 0.2s; }
input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-light); }

.btn { background: var(--primary); color: #fff; border: none; padding: 12px 20px; border-radius: 10px; cursor: pointer; font-size: 14px; font-weight: 600; transition: 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px; text-decoration: none; }
.btn:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); }
.btn.secondary { background: transparent; border: 1px solid var(--border); color: var(--text-main); } /* 保留部分次级按钮样式 */
.btn.danger { background: var(--danger-bg); color: var(--danger-text); }
.btn.danger:hover { background: var(--danger); color: #fff; }
.btn.icon { padding: 8px; width: 34px; height: 34px; border-radius: 8px; }

/* --- 进度条 --- */
.progress { width: 100%; height: 6px; background: var(--border); border-radius: 10px; overflow: hidden; margin-top: 8px; }
.progress-bar { height: 100%; background: var(--primary); border-radius: 10px; transition: width 0.5s ease; }

/* --- 模态框 --- */
.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(5px); animation: fadeIn 0.2s; }
.modal-content { background: var(--bg-card); margin: 8vh auto; padding: 30px; border-radius: 20px; width: 90%; max-width: 500px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); border: 1px solid var(--border); transform: scale(0.95); animation: scaleIn 0.3s forwards; position: relative; max-height: 85vh; overflow-y: auto; }
@keyframes scaleIn { to { transform: scale(1); opacity: 1; } }
.close-modal { position: absolute; right: 20px; top: 20px; font-size: 24px; cursor: pointer; color: var(--text-sub); }
.close-modal:hover { color: var(--text-main); }

/* --- 移动端适配 --- */
.mobile-nav { display: none; }
@media (max-width: 768px) {
    .sidebar { display: none; }
    .header { padding: 0 16px; }
    .content { padding: 16px; padding-bottom: 80px; }
    .stats-grid { grid-template-columns: 1fr; }
    .mobile-nav { display: flex; position: fixed; bottom: 0; left: 0; width: 100%; background: var(--bg-card); border-top: 1px solid var(--border); height: 60px; z-index: 100; justify-content: space-around; padding-bottom: env(safe-area-inset-bottom); }
    .nav-btn { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--text-sub); font-size: 10px; gap: 4px; }
    .nav-btn.active { color: var(--primary); }
    .nav-btn i { font-size: 20px; }
}

/* --- Toast --- */
.toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(20px); background: rgba(15, 23, 42, 0.9); color: #fff; padding: 12px 24px; border-radius: 50px; font-size: 14px; opacity: 0; visibility: hidden; transition: 0.3s; z-index: 2000; display: flex; align-items: center; gap: 8px; backdrop-filter: blur(10px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
.toast.show { opacity: 1; visibility: visible; transform: translateX(-50%) translateY(0); bottom: 80px; }
</style>
</head>
<body>

<div id="toast" class="toast"><i id="t-icon"></i><span id="t-msg"></span></div>

<div class="sidebar">
    <div class="brand"><i class="ri-globe-line"></i> GoRelay Pro</div>
    <div class="menu">
        <div class="item active" onclick="nav('dashboard',this)"><i class="ri-dashboard-3-line"></i> 概览</div>
        <div class="item" onclick="nav('rules',this)"><i class="ri-route-line"></i> 转发规则</div>
        <div class="item" onclick="nav('deploy',this)"><i class="ri-rocket-2-line"></i> 节点部署</div>
        <div class="item" onclick="nav('logs',this)"><i class="ri-file-list-3-line"></i> 系统日志</div>
        <div class="item" onclick="nav('settings',this)"><i class="ri-settings-4-line"></i> 系统设置</div>
    </div>
    <div class="user-panel">
        <div class="user-card">
            <div class="avatar">{{printf "%.1s" .User}}</div>
            <div class="user-meta">
                <div>{{.User}}</div>
                <div>管理员 (Admin)</div>
            </div>
        </div>
        <a href="/logout" class="btn-logout"><i class="ri-logout-box-r-line"></i> 安全退出</a>
    </div>
</div>

<div class="main">
    <header class="header">
        <div class="page-title"><i class="ri-dashboard-3-line" id="page-icon"></i> <span id="page-text">仪表盘</span></div>
        <div style="display:flex;gap:10px">
            <a href="https://github.com/jinhuaitao/relay" target="_blank" class="theme-toggle" style="text-decoration:none;color:var(--text-main)" title="项目源码">
                <i class="ri-github-line"></i>
            </a>
            <div class="theme-toggle" onclick="toggleTheme()"><i class="ri-moon-line" id="theme-icon"></i></div>
        </div>
    </header>

    <div class="content">
        <div id="dashboard" class="page active">
            <div class="stats-grid">
                <div class="card stat-item">
                    <div>
                        <div class="stat-label">累计总流量</div>
                        <div class="stat-val" id="stat-total-traffic">{{formatBytes .TotalTraffic}}</div>
                    </div>
                    <div class="stat-icon"><i class="ri-arrow-up-down-line"></i></div>
                </div>
                <div class="card stat-item">
                    <div>
                        <div class="stat-label">实时下载 (Rx)</div>
                        <div class="stat-val" id="speed-rx" style="color:#06b6d4">0 B/s</div>
                    </div>
                    <div class="stat-icon" style="color:#06b6d4;background:rgba(6,182,212,0.1);border-color:rgba(6,182,212,0.2)"><i class="ri-download-2-line"></i></div>
                </div>
                <div class="card stat-item">
                    <div>
                        <div class="stat-label">实时上传 (Tx)</div>
                        <div class="stat-val" id="speed-tx" style="color:#8b5cf6">0 B/s</div>
                    </div>
                    <div class="stat-icon" style="color:#8b5cf6;background:rgba(139,92,246,0.1);border-color:rgba(139,92,246,0.2)"><i class="ri-upload-2-line"></i></div>
                </div>
                <div class="card stat-item">
                    <div>
                        <div class="stat-label">在线节点</div>
                        <div class="stat-val">{{len .Agents}} <span style="font-size:14px;color:var(--text-sub);font-weight:500">/ {{len .Rules}} 规则</span></div>
                    </div>
                    <div class="stat-icon" style="color:#10b981;background:var(--success-bg);border-color:rgba(16,185,129,0.2)"><i class="ri-server-line"></i></div>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="card">
                    <h3><i class="ri-pulse-line"></i> 实时流量监控 (Tx/Rx)</h3>
                    <div style="height:320px;width:100%;"><canvas id="trafficChart"></canvas></div>
                </div>
                <div class="card">
                    <h3><i class="ri-pie-chart-line"></i> 流量分布 (Top 5)</h3>
                    <div style="height:320px;width:100%;display:flex;justify-content:center"><canvas id="pieChart"></canvas></div>
                </div>
            </div>

            <div class="card">
                <h3><i class="ri-server-line"></i> 节点状态监控</h3>
                <div class="table-container">
                    {{if .Agents}}
                    <table>
                        <thead><tr><th>状态</th><th>节点名称</th><th>远程 IP</th><th>系统负载 (Load)</th><th>操作</th></tr></thead>
                        <tbody>
                        {{range .Agents}}
                        <tr>
                            <td><span class="status-dot pulse" style="background:#10b981"></span></td>
                            <td><div style="font-weight:600">{{.Name}}</div></td>
                            <td><span class="click-copy" onclick="copyText('{{.RemoteIP}}')" style="font-family:monospace;background:var(--bg-body);padding:4px 8px;border-radius:6px;font-size:12px;cursor:pointer" title="点击复制">{{.RemoteIP}}</span></td>
                            <td style="width:200px">
                                <div style="display:flex;align-items:center;gap:10px">
                                    <div class="progress" style="margin:0;flex:1"><div class="progress-bar" id="load-bar-{{.Name}}" style="width:0%"></div></div>
                                    <span id="load-text-{{.Name}}" style="font-size:12px;font-family:monospace;min-width:60px">0.0</span>
                                </div>
                            </td>
                            <td><button class="btn danger icon" onclick="delAgent('{{.Name}}')" title="卸载节点"><i class="ri-delete-bin-line"></i></button></td>
                        </tr>
                        {{end}}
                        </tbody>
                    </table>
                    {{else}}
                    <div style="padding:40px;text-align:center;color:var(--text-sub)"><i class="ri-ghost-line" style="font-size:32px;margin-bottom:10px;display:block"></i>暂无在线节点</div>
                    {{end}}
                </div>
            </div>
        </div>

        <div id="rules" class="page">
            <div class="card">
                <h3><i class="ri-add-circle-line"></i> 新建转发规则</h3>
                <form action="/add" method="POST">
                    <div class="grid-form">
                        <div class="form-group"><label>备注名称</label><input name="note" placeholder="例如: 远程桌面" required></div>
                        <div class="form-group"><label>入口节点</label><select name="entry_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                        <div class="form-group"><label>入口端口</label><input type="number" name="entry_port" placeholder="1024-65535" required></div>
                        <div class="form-group"><label>出口节点</label><select name="exit_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                        <div class="form-group"><label>目标 IP (支持多IP/域名)</label><input name="target_ip" placeholder="192.168.1.1, 10.0.0.1" required></div>
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
                        <thead><tr><th>链路信息</th><th>目标地址</th><th>流量监控</th><th>状态</th><th>操作</th></tr></thead>
                        <tbody>
                        {{range .Rules}}
                        <tr style="{{if .Disabled}}opacity:0.6;filter:grayscale(1);{{end}}">
                            <td>
                                <div style="font-weight:700">{{if .Note}}{{.Note}}{{else}}未命名{{end}}</div>
                                <div style="font-size:12px;color:var(--text-sub);margin-top:4px;display:flex;align-items:center;gap:5px">
                                    <span style="background:var(--bg-body);padding:2px 6px;border-radius:4px">{{.EntryAgent}}:{{.EntryPort}}</span> <i class="ri-arrow-right-line"></i> <span style="background:var(--bg-body);padding:2px 6px;border-radius:4px">{{.ExitAgent}}</span>
                                </div>
                            </td>
                            <td>
                                <div style="font-family:monospace;font-size:13px">{{.TargetIP}}:{{.TargetPort}}</div>
                                <div style="font-size:11px;margin-top:2px" id="rule-latency-{{.ID}}"><i class="ri-pulse-line"></i> 检测中...</div>
                            </td>
                            <td style="min-width:180px">
                                <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                                    <span><i class="ri-user-line"></i> <span id="rule-uc-{{.ID}}">{{.UserCount}}</span></span>
                                    <span id="rule-traffic-{{.ID}}" style="font-family:monospace">{{formatBytes (add .TotalTx .TotalRx)}}</span>
                                </div>
                                {{if gt .TrafficLimit 0}}
                                <div class="progress"><div id="rule-bar-{{.ID}}" class="progress-bar" style="width:{{percent .TotalTx .TotalRx .TrafficLimit}}%"></div></div>
                                <div style="font-size:10px;color:var(--text-sub);margin-top:2px;display:flex;justify-content:space-between">
                                    <span id="rule-limit-text-{{.ID}}">已用 {{percent .TotalTx .TotalRx .TrafficLimit | printf "%.1f"}}%</span>
                                    <span>限额: {{formatBytes .TrafficLimit}}</span>
                                </div>
                                {{else}}
                                <div class="progress"><div class="progress-bar" style="width:100%;background:var(--success)"></div></div>
                                <div style="font-size:10px;color:var(--text-sub);margin-top:2px">无流量限制</div>
                                {{end}}
                            </td>
                            <td>
                                {{if .Disabled}}<span class="badge" style="background:var(--border);color:var(--text-sub)">已暂停</span>
                                {{else if and (gt .TrafficLimit 0) (ge (add .TotalTx .TotalRx) .TrafficLimit)}}<span class="badge danger">流量耗尽</span>
                                {{else}}<span class="badge success"><span class="badge-dot" id="rule-status-dot-{{.ID}}"></span> 运行中</span>{{end}}
                                <div style="font-size:10px;color:var(--text-sub);margin-top:4px">限速: {{formatSpeed .SpeedLimit}}</div>
                            </td>
                            <td>
                                <div style="display:flex;gap:6px">
                                    <button class="btn icon secondary" onclick="toggleRule('{{.ID}}')" title="切换状态">{{if .Disabled}}<i class="ri-play-fill" style="color:var(--success)"></i>{{else}}<i class="ri-pause-fill" style="color:var(--warning)"></i>{{end}}</button>
                                    <button class="btn icon secondary" onclick="openEdit('{{.ID}}','{{.Note}}','{{.EntryAgent}}','{{.EntryPort}}','{{.ExitAgent}}','{{.TargetIP}}','{{.TargetPort}}','{{.Protocol}}','{{.TrafficLimit}}','{{.SpeedLimit}}')" title="编辑"><i class="ri-edit-line"></i></button>
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
                <p style="color:var(--text-sub);font-size:14px;line-height:1.6">请在您的 VPS 或服务器（支持 Linux/macOS）上执行以下命令以安装 Agent 客户端。Agent 安装后将自动连接至本面板。</p>
                
                <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);margin-top:20px">
                    <div class="grid-form" style="margin-bottom:15px">
                        <div class="form-group"><label>给节点起个名字</label><input id="agentName" value="Node-01"></div>
                        <div class="form-group"><label>连接方式</label><select id="addrType"><option value="domain">使用域名 ({{.MasterDomain}})</option><option value="v4">使用 IPv4 ({{.MasterIP}})</option><option value="v6">使用 IPv6 ({{.MasterIPv6}})</option></select></div>
                    </div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:15px">
                        <button class="btn" onclick="genCmd()"><i class="ri-magic-line"></i> 生成命令</button>
                        <button class="btn secondary" onclick="copyCmd()"><i class="ri-file-copy-line"></i> 复制命令</button>
                    </div>
                    <div style="background:#1e293b;color:#f8fafc;padding:15px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;word-break:break-all;position:relative">
                        <div id="cmdText" style="opacity:0.7">请先点击“生成命令”按钮...</div>
                    </div>
                </div>
            </div>
        </div>

        <div id="logs" class="page">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
                    <h3><i class="ri-history-line"></i> 系统操作日志</h3>
                    <a href="/export_logs" class="btn secondary" style="text-decoration:none;font-size:13px"><i class="ri-download-line"></i> 导出日志</a>
                </div>
                <div class="table-container">
                    <table>
                        <thead><tr><th>时间</th><th>IP 来源</th><th>操作类型</th><th>详情</th></tr></thead>
                        <tbody id="log-table-body">
                        {{range .Logs}}
                        <tr>
                            <td style="font-family:monospace;color:var(--text-sub)">{{.Time}}</td>
                            <td>{{.IP}}</td>
                            <td><span class="badge" style="background:var(--input-bg);color:var(--text-main)">{{.Action}}</span></td>
                            <td style="color:var(--text-sub)">{{.Msg}}</td>
                        </tr>
                        {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="settings" class="page">
            <div class="card" style="max-width:700px">
                <h3><i class="ri-settings-line"></i> 系统全局设置</h3>
                <form action="/update_settings" method="POST">
                    <div class="grid-form" style="grid-template-columns: 1fr;">
                        <div class="form-group"><label>修改登录密码</label><input type="password" name="password" placeholder="留空则保持不变"></div>
                        <div class="form-group"><label>通信 Token (Agent 连接凭证)</label><input name="token" value="{{.Token}}"></div>
                        
                        <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border)">
                            <h4 style="margin:0 0 15px 0;font-size:14px"><i class="ri-telegram-line"></i> Telegram 通知配置</h4>
                            <div class="grid-form" style="gap:15px">
                                <div class="form-group"><label>Bot Token</label><input name="tg_bot_token" value="{{.Config.TgBotToken}}" placeholder="123456:ABC-DEF..."></div>
                                <div class="form-group"><label>Chat ID</label><input name="tg_chat_id" value="{{.Config.TgChatID}}" placeholder="-100xxxxxxx"></div>
                            </div>
                        </div>

                        <div style="background:var(--input-bg);padding:20px;border-radius:12px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
                            <div>
                                <h4 style="margin:0 0 5px 0;font-size:14px"><i class="ri-shield-keyhole-line"></i> 双因素认证 (2FA)</h4>
                                <div style="font-size:12px;color:var(--text-sub)">增加账户安全性，登录时需验证 OTP 动态码</div>
                            </div>
                            <div>
                                {{if .Config.TwoFAEnabled}}
                                <button type="button" class="btn danger" onclick="disable2FA()">关闭 2FA</button>
                                {{else}}
                                <button type="button" class="btn" onclick="enable2FA()">开启 2FA</button>
                                {{end}}
                            </div>
                        </div>

                        <div class="grid-form" style="gap:15px">
                            <div class="form-group"><label>面板域名</label><input name="master_domain" value="{{.MasterDomain}}"></div>
                            <div class="form-group"><label>面板 IP (IPv4)</label><input name="master_ip" value="{{.MasterIP}}"></div>
                            <div class="form-group"><label>面板 IP (IPv6)</label><input name="master_ipv6" value="{{.MasterIPv6}}"></div>
                        </div>

                        <div style="display:flex;gap:15px;margin-top:10px">
                            <button class="btn" style="flex:1"><i class="ri-save-3-line"></i> 保存配置</button>
                            <a href="/download_config" class="btn" style="flex:1"><i class="ri-download-cloud-2-line"></i> 备份配置</a>
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
        <span class="close-modal" onclick="closeEdit()">&times;</span>
        <h3 style="margin-top:0">修改规则</h3>
        <form action="/edit" method="POST">
            <input type="hidden" name="id" id="e_id">
            <div class="grid-form" style="grid-template-columns: 1fr 1fr;">
                <div class="form-group" style="grid-column: 1/-1"><label>备注</label><input name="note" id="e_note"></div>
                <div class="form-group"><label>入口节点</label><select name="entry_agent" id="e_entry">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group"><label>入口端口</label><input type="number" name="entry_port" id="e_eport"></div>
                <div class="form-group"><label>出口节点</label><select name="exit_agent" id="e_exit">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-group" style="grid-column: 1/-1"><label>目标地址</label><input name="target_ip" id="e_tip"></div>
                <div class="form-group"><label>目标端口</label><input type="number" name="target_port" id="e_tport"></div>
                <div class="form-group"><label>协议</label><select name="protocol" id="e_proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select></div>
                <div class="form-group"><label>流量限额</label><input type="number" step="0.1" name="traffic_limit" id="e_limit"></div>
                <div class="form-group"><label>带宽限速</label><input type="number" step="0.1" name="speed_limit" id="e_speed"></div>
                <div class="form-group" style="grid-column: 1/-1;margin-top:10px"><button class="btn" style="width:100%">保存修改</button></div>
            </div>
        </form>
    </div>
</div>

<div id="confirmModal" class="modal">
    <div class="modal-content" style="max-width:360px;text-align:center;padding-top:40px">
        <div style="font-size:48px;margin-bottom:16px" id="c_icon">⚠️</div>
        <h3 style="justify-content:center;margin-bottom:10px" id="c_title">确认操作</h3>
        <p style="color:var(--text-sub);margin-bottom:24px;line-height:1.5" id="c_msg"></p>
        <div style="display:flex;gap:10px">
            <button class="btn secondary" style="flex:1" onclick="closeConfirm()">取消</button>
            <button id="c_btn" class="btn danger" style="flex:1">确认</button>
        </div>
    </div>
</div>

<div id="twoFAModal" class="modal">
    <div class="modal-content" style="text-align:center;max-width:350px">
        <span class="close-modal" onclick="document.getElementById('twoFAModal').style.display='none'">&times;</span>
        <h3 style="justify-content:center">绑定 2FA</h3>
        <p style="font-size:13px;color:var(--text-sub)">请使用 Google Authenticator 扫描下方二维码</p>
        <img id="qrImage" style="width:200px;height:200px;border-radius:12px;margin:10px 0 20px 0;border:1px solid var(--border)">
        <input id="twoFACode" placeholder="输入 6 位验证码" style="text-align:center;letter-spacing:4px;font-size:18px;margin-bottom:15px">
        <button class="btn" onclick="verify2FA()" style="width:100%">验证并开启</button>
    </div>
</div>

<script>
    // --- 核心逻辑 ---
    var m_domain="{{.MasterDomain}}", m_v4="{{.MasterIP}}", m_v6="{{.MasterIPv6}}", port="9999", token="{{.Token}}", dwUrl="{{.DownloadURL}}", is_tls={{.IsTLS}};

    function nav(id, el) {
        document.querySelectorAll('.page').forEach(e => e.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        
        const titles = {'dashboard':'仪表盘', 'deploy':'节点部署', 'rules':'转发规则', 'logs':'系统日志', 'settings':'系统设置'};
        const icons = {'dashboard':'ri-dashboard-3-line', 'deploy':'ri-rocket-2-line', 'rules':'ri-route-line', 'logs':'ri-file-list-3-line', 'settings':'ri-settings-4-line'};
        document.getElementById('page-text').innerText = titles[id];
        document.getElementById('page-icon').className = icons[id];
        
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

    // 复制文本
    function copyText(txt) {
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(txt).then(() => showToast("已复制: "+txt, "success"));
        else {
            const ta = document.createElement("textarea"); ta.value = txt; ta.style.position="fixed"; ta.style.left="-9999px";
            document.body.appendChild(ta); ta.focus(); ta.select();
            try { document.execCommand('copy'); showToast("已复制", "success"); } catch(e) { showToast("复制失败", "warn"); }
            document.body.removeChild(ta);
        }
    }

    // 主题切换
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

    // Toast 提示
    function showToast(msg, type) {
        const box = document.getElementById('toast');
        const icon = document.getElementById('t-icon');
        document.getElementById('t-msg').innerText = msg;
        box.className = 'toast show';
        if(type === 'warn') { icon.className = 'ri-error-warning-line'; box.style.background = 'var(--warning-bg)'; box.style.color = 'var(--warning-text)'; }
        else if(type === 'success') { icon.className = 'ri-checkbox-circle-line'; box.style.background = '#10b981'; box.style.color = '#fff'; }
        else { icon.className = 'ri-information-line'; box.style.background = '#0f172a'; box.style.color = '#fff'; }
        setTimeout(() => box.className = 'toast', 3000);
    }

    // 确认框
    function showConfirm(title, msg, type, cb) {
        document.getElementById('c_title').innerText = title;
        document.getElementById('c_msg').innerHTML = msg;
        const btn = document.getElementById('c_btn');
        const icon = document.getElementById('c_icon');
        if(type === 'danger') { btn.className = 'btn danger'; btn.innerText = '确认删除'; icon.innerText = '🗑️'; } 
        else { btn.className = 'btn'; btn.innerText = '确认执行'; icon.innerText = '🤔'; }
        btn.onclick = function() { closeConfirm(); cb(); };
        document.getElementById('confirmModal').style.display = 'block';
    }
    function closeConfirm() { document.getElementById('confirmModal').style.display = 'none'; }

    // 部署命令逻辑
    function genCmd() {
        const n = document.getElementById('agentName').value;
        const t = document.getElementById('addrType').value;
        const host = (t === "domain") ? (m_domain || location.hostname) : (t === "v4" ? m_v4 : '['+m_v6+']');
        if(!host || host === "[]") { showToast("请先配置 Master 地址", "warn"); return; }
        let cmd = 'curl -L -o /root/relay '+dwUrl+' && chmod +x /root/relay && /root/relay -service install -mode agent -name "'+n+'" -connect "'+host+':'+port+'" -token "'+token+'"';
        if(is_tls) cmd += ' -tls';
        document.getElementById('cmdText').innerText = cmd;
        document.getElementById('cmdText').style.opacity = '1';
        showToast("命令已生成", "success");
    }
    function copyCmd() { copyText(document.getElementById('cmdText').innerText); }

    // 规则操作
    function delRule(id) { showConfirm("删除规则", "删除后该端口将立即停止服务，确定吗？", "danger", () => location.href="/delete?id="+id); }
    function toggleRule(id) { location.href="/toggle?id="+id; }
    function resetTraffic(id) { showConfirm("重置流量", "确定要清零该规则的流量统计吗？", "normal", () => location.href="/reset_traffic?id="+id); }
    function delAgent(name) { showConfirm("卸载节点", "确定要卸载节点 <b>"+name+"</b> 吗？<br>这将向节点发送自毁指令。", "danger", () => location.href="/delete_agent?name="+name); }

    // 编辑
    function openEdit(id, note, entry, eport, exit, tip, tport, proto, limit, speed) {
        document.getElementById('e_id').value = id;
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

    // 2FA
    var tempSecret = "";
    function enable2FA() { fetch('/2fa/generate').then(r=>r.json()).then(d => { tempSecret = d.secret; document.getElementById('qrImage').src = d.qr; document.getElementById('twoFAModal').style.display = 'block'; }); }
    function verify2FA() { fetch('/2fa/verify', {method:'POST', body:JSON.stringify({secret:tempSecret, code:document.getElementById('twoFACode').value})}).then(r=>r.json()).then(d => { if(d.success) { showToast("2FA 已开启", "success"); setTimeout(()=>location.reload(), 1000); } else alert("验证码错误"); }); }
    function disable2FA() { showConfirm("关闭 2FA", "关闭后账户安全性将降低，确定吗？", "danger", () => { fetch('/2fa/disable').then(r=>r.json()).then(d => { if(d.success) location.reload(); }); }); }

    // --- Chart.js: 实时流量 (双线: Tx, Rx) ---
    var ctx = document.getElementById('trafficChart').getContext('2d');
    
    // 创建渐变
    var txGrad = ctx.createLinearGradient(0, 0, 0, 300);
    txGrad.addColorStop(0, 'rgba(139, 92, 246, 0.4)'); // Violet
    txGrad.addColorStop(1, 'rgba(139, 92, 246, 0)');
    
    var rxGrad = ctx.createLinearGradient(0, 0, 0, 300);
    rxGrad.addColorStop(0, 'rgba(6, 182, 212, 0.4)'); // Cyan
    rxGrad.addColorStop(1, 'rgba(6, 182, 212, 0)');

    var chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [
                {
                    label: '上传 (Tx)',
                    data: Array(30).fill(0),
                    borderColor: '#8b5cf6',
                    backgroundColor: txGrad,
                    borderWidth: 2,
                    pointRadius: 0,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: '下载 (Rx)',
                    data: Array(30).fill(0),
                    borderColor: '#06b6d4',
                    backgroundColor: rxGrad,
                    borderWidth: 2,
                    pointRadius: 0,
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: true }, tooltip: { mode: 'index', intersect: false } },
            scales: {
                x: { display: false },
                y: { beginAtZero: true, grid: { color: 'rgba(128, 128, 128, 0.1)', borderDash: [5, 5] }, ticks: { callback: v => formatBytes(v)+'/s', color: '#94a3b8' } }
            },
            animation: { duration: 0 },
            interaction: { mode: 'nearest', axis: 'x', intersect: false }
        }
    });

    // --- Chart.js: 流量占比饼图 ---
    var ctxPie = document.getElementById('pieChart').getContext('2d');
    var pieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#6366f1', '#ec4899', '#f59e0b', '#10b981', '#3b82f6'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: '#94a3b8', boxWidth: 12 } } },
            cutout: '70%'
        }
    });

    function updateChartTheme(theme) {
        chart.options.scales.y.grid.color = theme === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';
        chart.update();
    }

    // --- WS 数据处理 ---
    function formatBytes(b) {
        if(b==0) return "0 B";
        const u = 1024, i = Math.floor(Math.log(b)/Math.log(u));
        return parseFloat((b / Math.pow(u, i)).toFixed(2)) + " " + ["B","KB","MB","GB","TB"][i];
    }

    function connectWS() {
        const ws = new WebSocket((location.protocol==='https:'?'wss:':'ws:') + '//' + location.host + '/ws');
        ws.onmessage = function(e) {
            try {
                const msg = JSON.parse(e.data);
                if(msg.type === 'stats' && msg.data) {
                    const d = msg.data;
                    document.getElementById('stat-total-traffic').innerText = formatBytes(d.total_traffic);
                    
                    // 实时速度
                    document.getElementById('speed-rx').innerText = formatBytes(d.speed_rx) + '/s';
                    document.getElementById('speed-tx').innerText = formatBytes(d.speed_tx) + '/s';
                    
                    // 更新线图
                    chart.data.datasets[0].data.push(d.speed_tx);
                    chart.data.datasets[0].data.shift();
                    chart.data.datasets[1].data.push(d.speed_rx);
                    chart.data.datasets[1].data.shift();
                    chart.update();

                    // 更新饼图 (Top 5 流量规则)
                    if (d.rules) {
                        const sortedRules = [...d.rules].sort((a,b) => b.total - a.total).slice(0, 5);
                        pieChart.data.labels = sortedRules.map(r => r.name || '未命名');
                        pieChart.data.datasets[0].data = sortedRules.map(r => r.total);
                        pieChart.update();
                    }

                    // 更新节点负载
                    if(d.agents) d.agents.forEach(a => {
                        const loadText = document.getElementById('load-text-'+a.name);
                        const loadBar = document.getElementById('load-bar-'+a.name);
                        if(loadText && loadBar) {
                            let loadStr = a.sys_status; 
                            // 简单解析 Load: 0.05 | Mem ...
                            let loadVal = 0;
                            if(loadStr.includes("Load:")) {
                                let parts = loadStr.split("|");
                                loadVal = parseFloat(parts[0].replace("Load:", "").trim()) || 0;
                            }
                            loadText.innerText = loadVal.toFixed(2);
                            let pct = loadVal * 20; // 假设 Load 5 = 100%
                            if (pct > 100) pct = 100;
                            loadBar.style.width = pct + "%";
                            loadBar.style.background = pct > 80 ? "#ef4444" : "#6366f1";
                        }
                    });
                    
                    // 更新规则列表状态
                    if(d.rules) {
                        d.rules.forEach(r => {
                            const traf = document.getElementById('rule-traffic-'+r.id); if(traf) traf.innerText = formatBytes(r.total);
                            const uc = document.getElementById('rule-uc-'+r.id); if(uc) uc.innerText = r.uc;
                            const lat = document.getElementById('rule-latency-'+r.id);
                            const dot = document.getElementById('rule-status-dot-'+r.id);
                            
                            if(lat && dot) {
                                if(r.status) {
                                    lat.innerHTML = '<i class="ri-pulse-line" style="color:#10b981"></i> ' + r.latency + ' ms';
                                    dot.parentElement.className = 'badge success'; dot.parentElement.innerHTML = '<span class="badge-dot"></span> 正常';
                                } else {
                                    lat.innerHTML = '<i class="ri-error-warning-line" style="color:#ef4444"></i> 离线';
                                    dot.parentElement.className = 'badge danger'; dot.parentElement.innerHTML = '<span class="badge-dot"></span> 异常';
                                }
                            }
                            if(r.limit > 0) {
                                let pct = (r.total / r.limit) * 100; if(pct > 100) pct = 100;
                                const bar = document.getElementById('rule-bar-'+r.id);
                                if(bar) { bar.style.width = pct + '%'; bar.style.background = pct > 90 ? '#ef4444' : '#6366f1'; }
                                const txt = document.getElementById('rule-limit-text-'+r.id);
                                if(txt) txt.innerText = '已用 ' + pct.toFixed(1) + '%';
                            }
                        });
                    }

                    if(d.logs && document.getElementById('logs').classList.contains('active')) {
                        const tbody = document.getElementById('log-table-body');
                        let html = '';
                        d.logs.forEach(l => {
                            html += '<tr><td style="font-family:monospace;color:var(--text-sub)">'+l.time+'</td>'+
                                    '<td>'+l.ip+'</td>'+
                                    '<td><span class="badge" style="background:var(--input-bg);color:var(--text-main)">'+l.action+'</span></td>'+
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
