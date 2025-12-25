package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
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

	"github.com/gorilla/websocket"
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
	SpeedLimit   int64  `json:"speed_limit"` // Bytes/s

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
	CurrentSpeed int64             `json:"current_speed"`
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
	
	activeTasks      sync.Map // 用于检测配置变更
	activeTargets    sync.Map // 用于健康检查
	
	agentTraffic     sync.Map
	agentUserCounts  sync.Map
	targetHealthMap  sync.Map 
	
	sessions         = make(map[string]time.Time)
	configDirty      int32

	wsUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	wsClients  = make(map[*websocket.Conn]bool)
	wsMu       sync.Mutex
)

// --- 主程序 ---

func main() {
	setRLimit()

	mode := flag.String("mode", "master", "运行模式")
	name := flag.String("name", "", "Agent名称")
	connect := flag.String("connect", "", "Master地址")
	token := flag.String("token", "", "通信Token")
	serviceOp := flag.String("service", "", "install | uninstall")

	flag.Parse()

	if *serviceOp != "" {
		handleService(*serviceOp, *mode, *name, *connect, *token)
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

func handleService(op, mode, name, connect, token string) {
	if os.Geteuid() != 0 {
		log.Fatal("需 root 权限")
	}
	exe, _ := os.Executable()
	exe, _ = filepath.Abs(exe)
	args := fmt.Sprintf("-mode %s -name \"%s\" -connect \"%s\" -token \"%s\"", mode, name, connect, token)
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
		ln, err := net.Listen("tcp", ControlPort)
		if err != nil {
			log.Fatal(err)
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
	var lastTotalTraffic int64 = 0

	for range ticker.C {
		mu.Lock()
		var currentTotal int64
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
			t := r.TotalTx + r.TotalRx
			currentTotal += t
			ruleData = append(ruleData, RuleStatusData{
				ID:        r.ID,
				Total:     t,
				UserCount: r.UserCount,
				Limit:     r.TrafficLimit,
				Status:    r.TargetStatus,
				Latency:   r.TargetLatency,
			})
		}
		mu.Unlock()

		var speed int64 = 0
		if lastTotalTraffic != 0 {
			speed = currentTotal - lastTotalTraffic
		}
		if speed < 0 {
			speed = 0
		}
		lastTotalTraffic = currentTotal

		wsMu.Lock()
		if len(wsClients) == 0 {
			wsMu.Unlock()
			continue
		}

		msg := WSMessage{
			Type: "stats",
			Data: WSDashboardData{
				TotalTraffic: currentTotal,
				CurrentSpeed: speed,
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
	}{al, displayRules, displayLogs, config.AgentToken, config.WebUser, DownloadURL, totalTraffic, config.MasterIP, config.MasterIPv6, config.MasterDomain, config}

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
		config.WebPass = md5Hash(r.FormValue("password"))
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
	if r.Method == "POST" {
		mu.Lock()
		u, p := config.WebUser, config.WebPass
		mu.Unlock()
		if r.FormValue("username") == u && md5Hash(r.FormValue("password")) == p {
			sid := make([]byte, 16)
			rand.Read(sid)
			sidStr := hex.EncodeToString(sid)
			mu.Lock()
			sessions[sidStr] = time.Now().Add(12 * time.Hour)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true})
			addLog(r, "登录成功", "管理员登录面板")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	t, _ := template.New("l").Parse(loginHtml)
	t.Execute(w, nil)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	addLog(r, "退出登录", "管理员退出面板")
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

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
		config.WebPass = md5Hash(p)
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
		conn, err := net.Dial("tcp", masterAddr)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		json.NewEncoder(conn).Encode(Message{Type: "auth", Payload: map[string]string{"name": name, "token": token}})

		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(3 * time.Second)
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

// --- [关键升级] 主动感知健康状态的 TCP 转发 ---
func pipeTCP(src net.Conn, targetStr, tid string, limit int64) {
	defer src.Close()
	allTargets := strings.Split(targetStr, ",")
	
	// 1. 筛选健康节点
	var healthyTargets []string
	for _, t := range allTargets {
		t = strings.TrimSpace(t)
		if t == "" { continue }
		if status, ok := targetHealthMap.Load(t); ok && status.(bool) {
			healthyTargets = append(healthyTargets, t)
		}
	}

	// 2. 如果没有健康节点，回退到尝试所有节点
	candidates := healthyTargets
	if len(candidates) == 0 {
		candidates = []string{}
		for _, t := range allTargets {
			if strings.TrimSpace(t) != "" { candidates = append(candidates, strings.TrimSpace(t)) }
		}
	}

	// 3. 随机选择一个开始尝试 (负载均衡)
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
				// UDP 会话超时更短一些，以便快速切换后端
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
			// 新会话：优先选健康的
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

// 核心限速算法 (Pacer)
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

func md5Hash(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
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
<html lang="zh" data-theme="light">
<head>
<title>初始化配置 - GoRelay</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<style>
:root {
    --primary: #6366f1; --primary-hover: #4f46e5;
    --bg-body: #f8fafc; --bg-card: #ffffff;
    --text-main: #1e293b; --text-sub: #64748b;
    --border: #e2e8f0; --input-bg: #ffffff;
    --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
}
[data-theme="dark"] {
    --primary: #818cf8; --primary-hover: #6366f1;
    --bg-body: #0f172a; --bg-card: #1e293b;
    --text-main: #f1f5f9; --text-sub: #94a3b8;
    --border: #334155; --input-bg: #0f172a;
    --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
}
body { background: var(--bg-body); color: var(--text-main); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; transition: background .3s, color .3s; }
.card { background: var(--bg-card); padding: 40px; border-radius: 24px; box-shadow: var(--shadow); width: 100%; max-width: 400px; border: 1px solid var(--border); }
h2 { text-align: center; margin-bottom: 30px; font-weight: 800; color: var(--text-main); }
label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600; color: var(--text-sub); }
input { width: 100%; padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: var(--input-bg); color: var(--text-main); outline: none; transition: .2s; box-sizing: border-box; margin-bottom: 20px; font-size: 15px; }
input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); }
button { width: 100%; padding: 14px; background: var(--primary); color: #fff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: .2s; }
button:hover { background: var(--primary-hover); transform: translateY(-1px); }
</style>
</head>
<body>
<form class="card" method="POST">
    <h2>🚀 系统初始化</h2>
    <label>设置管理员账号</label><input name="username" placeholder="Admin" required>
    <label>设置管理员密码</label><input type="password" name="password" placeholder="Password" required>
    <label>通信 Token (用于节点连接)</label><input name="token" placeholder="SecureToken123" required>
    <button>完成设置并启动</button>
</form>
</body>
</html>`

const loginHtml = `<!DOCTYPE html>
<html lang="zh" data-theme="light">
<head>
<title>登录 - GoRelay Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<style>
:root {
    --primary: #6366f1; --primary-hover: #4f46e5;
    --bg-body: #f8fafc; --bg-card: #ffffff;
    --text-main: #1e293b; --text-sub: #64748b;
    --border: #e2e8f0; --input-bg: #ffffff;
    --shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
}
[data-theme="dark"] {
    --primary: #818cf8; --primary-hover: #6366f1;
    --bg-body: #0f172a; --bg-card: #1e293b;
    --text-main: #f1f5f9; --text-sub: #94a3b8;
    --border: #334155; --input-bg: #0f172a;
    --shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
}
body { background: var(--bg-body); color: var(--text-main); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; transition: background .3s, color .3s; position: relative; overflow: hidden; }
.blob { position: absolute; width: 500px; height: 500px; background: var(--primary); opacity: 0.1; filter: blur(80px); border-radius: 50%; z-index: -1; animation: float 10s infinite ease-in-out; }
@keyframes float { 0%,100%{transform:translate(0,0)} 50%{transform:translate(30px, -30px)} }
.card { background: var(--bg-card); padding: 48px 40px; border-radius: 24px; box-shadow: var(--shadow); width: 100%; max-width: 360px; border: 1px solid var(--border); backdrop-filter: blur(10px); }
.brand { text-align: center; margin-bottom: 30px; }
.brand h2 { margin: 10px 0 5px; font-weight: 800; font-size: 28px; background: linear-gradient(135deg, var(--primary) 0%, #a855f7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.brand p { margin: 0; color: var(--text-sub); font-size: 14px; }
input { width: 100%; padding: 14px 16px; border: 1px solid var(--border); border-radius: 12px; background: var(--input-bg); color: var(--text-main); outline: none; transition: .2s; box-sizing: border-box; margin-bottom: 20px; font-size: 15px; }
input:focus { border-color: var(--primary); box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.15); }
button { width: 100%; padding: 14px; background: var(--primary); color: #fff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: .2s; box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.3); }
button:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.4); }
.theme-toggle { position: absolute; top: 30px; right: 30px; width: 40px; height: 40px; background: transparent; border: none; color: var(--text-main); font-size: 22px; cursor: pointer; display: flex; align-items: center; justify-content: center; z-index: 10; outline: none; -webkit-tap-highlight-color: transparent; opacity: 0.8; }
.theme-toggle:hover { opacity: 1; transform: scale(1.1); }
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()" id="themeBtn">🌗</button>
<div class="blob" style="top:-100px;left:-100px;"></div>
<div class="blob" style="bottom:-100px;right:-100px;animation-delay: -5s"></div>
<form class="card" method="POST">
    <div class="brand"><h2>GoRelay Pro</h2><p>安全高效的内网穿透管理系统</p></div>
    <input name="username" placeholder="账号 / Username" required>
    <input type="password" name="password" placeholder="密码 / Password" required>
    <button>立即登录</button>
</form>
<script>
    function toggleTheme() {
        const html = document.documentElement;
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    }
    const saved = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', saved);
</script>
</body>
</html>`

const dashboardHtml = `
<!DOCTYPE html>
<html lang="zh" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1e293b" media="(prefers-color-scheme: dark)">
<title>GoRelay Pro</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
/* --- 全局变量与重置 --- */
:root {
    --primary: #6366f1; --primary-hover: #4f46e5;
    --bg-body: #f1f5f9; --bg-sidebar: #0f172a;
    --bg-card: #ffffff; --bg-hover: #f8fafc;
    --text-main: #0f172a; --text-sub: #64748b; --text-inv: #ffffff;
    --border: #e2e8f0; --input-bg: #ffffff;
    --success: #10b981; --success-bg: #d1fae5; --success-text: #065f46;
    --danger: #ef4444; --danger-bg: #fee2e2; --danger-text: #991b1b;
    --warning: #f59e0b; --warning-bg: #fef3c7; --warning-text: #fef3c7;
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -1px rgba(0,0,0,0.03);
    --radius: 16px;
    --sidebar-w: 260px;
    --header-h: 60px;
    --safe-top: env(safe-area-inset-top, 0px);
    --safe-bot: env(safe-area-inset-bottom, 0px);
    --bot-nav-h: 60px;
}
[data-theme="dark"] {
    --primary: #818cf8; --primary-hover: #6366f1;
    --bg-body: #020617; --bg-sidebar: #0f172a;
    --bg-card: #1e293b; --bg-hover: #334155;
    --text-main: #f8fafc; --text-sub: #94a3b8; --text-inv: #ffffff;
    --border: #334155; --input-bg: #0f172a;
    --success: #34d399; --success-bg: #064e3b; --success-text: #d1fae5;
    --danger: #f87171; --danger-bg: #7f1d1d; --danger-text: #fee2e2;
    --warning: #fbbf24; --warning-bg: #78350f; --warning-text: #fef3c7;
    --shadow: 0 10px 15px -3px rgba(0,0,0,0.4);
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg-body); color: var(--text-main); height: 100vh; display: flex; overflow: hidden; transition: background .3s, color .3s; }
.sidebar { width: var(--sidebar-w); background: var(--bg-sidebar); color: var(--text-inv); display: flex; flex-direction: column; flex-shrink: 0; z-index: 50; }
.brand { height: var(--header-h); display: flex; align-items: center; padding: 0 24px; font-size: 20px; font-weight: 800; border-bottom: 1px solid rgba(255,255,255,0.1); letter-spacing: -0.5px; }
.brand span { color: var(--primary); margin-right: 8px; font-size: 24px; }
.menu { flex: 1; padding: 24px 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; }
.item { display: flex; align-items: center; padding: 12px 16px; color: #94a3b8; text-decoration: none; cursor: pointer; border-radius: 12px; transition: .2s; font-size: 14px; font-weight: 600; }
.item:hover { background: rgba(255,255,255,0.05); color: #fff; }
.item.active { background: var(--primary); color: #fff; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4); }
.item .icon { margin-right: 12px; font-size: 18px; width: 24px; text-align: center; }
.user-panel { padding: 20px; background: rgba(0,0,0,0.2); border-top: 1px solid rgba(255,255,255,0.1); }
.user-info { font-size: 13px; font-weight: 600; margin-bottom: 10px; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
.logout { display: block; text-align: center; background: rgba(255,255,255,0.1); color: #fff; text-decoration: none; padding: 10px; border-radius: 8px; font-size: 12px; transition: .2s; }
.logout:hover { background: var(--danger); }
.bottom-nav { display: none; }
.main-wrapper { flex: 1; display: flex; flex-direction: column; position: relative; width: 100%; }
.header { height: calc(var(--header-h) + var(--safe-top)); background: var(--bg-card); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: var(--safe-top) 24px 0 24px; flex-shrink: 0; transition: background .3s; }
.header-title { font-weight: 700; font-size: 18px; }
.theme-btn { font-size: 20px; cursor: pointer; background: var(--bg-body); border: 1px solid var(--border); width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; transition: .2s; }
.theme-btn:hover { background: var(--border); }
.content { flex: 1; padding: 24px; overflow-y: auto; overflow-x: hidden; scroll-behavior: smooth; }
.page { display: none; animation: slideUp .3s ease-out; max-width: 1200px; margin: 0 auto; }
.page.active { display: block; }
@keyframes slideUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.card { background: var(--bg-card); padding: 24px; border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 24px; border: 1px solid var(--border); }
h3 { margin: 0 0 20px 0; font-size: 18px; color: var(--text-main); font-weight: 700; display: flex; align-items: center; gap: 8px; }
h3::before { content: ''; width: 4px; height: 18px; background: var(--primary); border-radius: 2px; display: inline-block; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 24px; }
.stat-card { background: var(--bg-card); padding: 24px; border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; position: relative; overflow: hidden; }
.stat-card::after { content: ''; position: absolute; right: -20px; top: -20px; width: 100px; height: 100px; background: var(--primary); opacity: 0.05; border-radius: 50%; pointer-events: none; }
.stat-info .val { font-size: 28px; font-weight: 800; color: var(--text-main); line-height: 1.2; letter-spacing: -1px; }
.stat-info .lbl { color: var(--text-sub); font-size: 13px; font-weight: 600; margin-top: 4px; }
.stat-icon { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
.table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 12px; border: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; white-space: nowrap; }
th { text-align: left; padding: 14px 20px; color: var(--text-sub); font-size: 12px; font-weight: 700; text-transform: uppercase; background: var(--bg-body); border-bottom: 1px solid var(--border); }
td { padding: 16px 20px; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--text-main); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg-hover); }
.badge { padding: 4px 10px; border-radius: 99px; font-size: 12px; font-weight: 700; background: var(--success-bg); color: var(--success-text); display: inline-flex; align-items: center; gap: 4px; }
.badge.danger { background: var(--danger-bg); color: var(--danger-text); }
.badge::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.prog-container { width: 100%; background: var(--border); border-radius: 99px; height: 6px; margin-top: 8px; overflow: hidden; }
.prog-bar { height: 100%; background: var(--primary); border-radius: 99px; transition: width .4s ease; }
.prog-limit { font-size: 12px; color: var(--text-sub); margin-top: 6px; display: flex; justify-content: space-between; font-weight: 500; }
.grid-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; align-items: end; }
.form-g { margin-bottom: 0; }
label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; color: var(--text-main); }
input, select { width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; background: var(--input-bg); color: var(--text-main); font-size: 14px; outline: none; transition: .2s; }
input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15); }
button { background: var(--primary); color: #fff; border: none; padding: 11px 20px; border-radius: 10px; cursor: pointer; font-size: 14px; font-weight: 600; transition: .2s; display: inline-flex; align-items: center; justify-content: center; gap: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
button:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
.btn-sec { background: var(--bg-body); color: var(--text-main); border: 1px solid var(--border); box-shadow: none; }
.btn-sec:hover { background: var(--bg-hover); border-color: var(--text-sub); }
.btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 8px; }
.btn-del { background: var(--danger-bg); color: var(--danger-text); border: 1px solid transparent; box-shadow: none; padding: 6px 10px; }
.btn-del:hover { background: var(--danger); color: #fff; }
pre { background: #1e293b; color: #f8fafc; padding: 20px; border-radius: 12px; font-family: "JetBrains Mono", Consolas, monospace; font-size: 13px; line-height: 1.6; overflow-x: auto; border: 1px solid var(--border); margin-top: 10px; position: relative; }
.modal { display: none; position: fixed; z-index: 999; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); backdrop-filter: blur(4px); animation: fadeIn .2s; }
.modal-content { background: var(--bg-card); margin: 5vh auto; padding: 30px; border-radius: 20px; width: 90%; max-width: 600px; position: relative; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); animation: scaleIn .3s cubic-bezier(0.16, 1, 0.3, 1); border: 1px solid var(--border); max-height: 70vh; overflow-y: auto; }
@keyframes scaleIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
.close { position: absolute; right: 24px; top: 24px; font-size: 24px; cursor: pointer; color: var(--text-sub); transition: .2s; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: var(--bg-body); }
.close:hover { color: var(--text-main); background: var(--border); }
.confirm-modal-body { text-align: center; }
.confirm-icon { font-size: 48px; margin-bottom: 16px; animation: popIn 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275); display: inline-block; }
@keyframes popIn { 0% { opacity: 0; transform: scale(0.5); } 100% { opacity: 1; transform: scale(1); } }
.confirm-title { font-size: 20px; font-weight: 800; color: var(--text-main); margin-bottom: 10px; }
.confirm-text { font-size: 14px; color: var(--text-sub); margin-bottom: 24px; line-height: 1.6; }
.confirm-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.confirm-actions button { width: 100%; padding: 12px; font-size: 14px; }
.toast-box { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: rgba(0,0,0,0.8); color: #fff; padding: 12px 24px; border-radius: 50px; font-size: 14px; opacity: 0; visibility: hidden; transition: .3s; z-index: 2000; display: flex; align-items: center; gap: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); backdrop-filter: blur(5px); }
.toast-box.show { opacity: 1; visibility: visible; bottom: 80px; } 
.toast-icon { font-size: 18px; }
@media (max-width: 768px) {
    .sidebar { display: none; }
    .header { padding-left: 16px; padding-right: 16px; }
    .header-title { display: block; font-size: 20px; }
    .content { padding: 16px; padding-bottom: calc(var(--bot-nav-h) + var(--safe-bot) + 20px); }
    .stats { grid-template-columns: 1fr; gap: 12px; }
    .grid-form { grid-template-columns: 1fr; }
    .modal-content { margin: 10vh auto; width: 85%; padding: 24px; }
    .bottom-nav { display: flex; position: fixed; bottom: 0; left: 0; right: 0; height: calc(var(--bot-nav-h) + var(--safe-bot)); background: rgba(255,255,255,0.85); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-top: 1px solid rgba(0,0,0,0.05); z-index: 1000; padding-bottom: var(--safe-bot); box-shadow: 0 -5px 20px rgba(0,0,0,0.03); }
    [data-theme="dark"] .bottom-nav { background: rgba(30, 41, 59, 0.85); border-top: 1px solid rgba(255,255,255,0.05); }
    .nav-item { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--text-sub); font-size: 10px; font-weight: 500; cursor: pointer; transition: .2s; -webkit-tap-highlight-color: transparent; }
    .nav-item.active { color: var(--primary); }
    .nav-icon { font-size: 24px; margin-bottom: 2px; transition: .2s; }
    .nav-item.active .nav-icon { transform: translateY(-2px); }
}
</style>
</head>
<body>
<div id="toast" class="toast-box"><span id="t-icon" class="toast-icon"></span><span id="t-msg"></span></div>

<div class="sidebar">
    <div class="brand"><span>⚡</span> GoRelay Pro</div>
    <div class="menu">
        <a class="item active" onclick="nav('dashboard',this)"><span class="icon">📊</span> 仪表盘</a>
        <a class="item" onclick="nav('deploy',this)"><span class="icon">🚀</span> 节点部署</a>
        <a class="item" onclick="nav('rules',this)"><span class="icon">🔗</span> 转发规则</a>
        <a class="item" onclick="nav('logs',this)"><span class="icon">🛡️</span> 操作日志</a>
        <a class="item" onclick="nav('settings',this)"><span class="icon">⚙️</span> 系统设置</a>
    </div>
    <div class="user-panel">
        <div class="user-info">
            <div style="width:32px;height:32px;background:var(--primary);border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold">A</div>
            <div><div>{{.User}}</div><div style="font-size:10px;opacity:0.7;font-weight:400">管理员</div></div>
        </div>
        <a href="/logout" class="logout">安全退出</a>
    </div>
</div>

<div class="main-wrapper">
    <header class="header">
        <div class="header-title">仪表盘</div>
        <button class="theme-btn" onclick="toggleTheme()" id="themeIcon">🌗</button>
    </header>

    <div class="content">
        <div id="dashboard" class="page active">
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-info"><div class="val" id="stat-total-traffic">{{formatBytes .TotalTraffic}}</div><div class="lbl">累计消耗流量</div></div>
                    <div class="stat-icon" style="background:rgba(99, 102, 241, 0.1);color:var(--primary)">📶</div>
                </div>
                <div class="stat-card">
                    <div class="stat-info"><div class="val">{{len .Agents}}</div><div class="lbl">在线节点数量</div></div>
                    <div class="stat-icon" style="background:var(--success-bg);color:var(--success-text)">📡</div>
                </div>
                <div class="stat-card">
                    <div class="stat-info"><div class="val">{{len .Rules}}</div><div class="lbl">运行规则总数</div></div>
                    <div class="stat-icon" style="background:var(--warning-bg);color:var(--warning-text)">⚡</div>
                </div>
            </div>

            <div class="card">
                <h3 style="display:flex;justify-content:space-between;">
                    <span>📈 实时网络流量趋势</span>
                    <span id="current-speed" style="font-size:14px;font-weight:600;color:var(--primary)">0 B/s</span>
                </h3>
                <div style="height:250px;width:100%;position:relative;"><canvas id="trafficChart"></canvas></div>
            </div>
            
            <div class="card">
                <h3>节点状态监控</h3>
                <div class="table-responsive">
                    {{if .Agents}}
                    <table><thead><tr><th>节点名称</th><th>IP 地址</th><th>连接状态 / 负载</th><th>操作</th></tr></thead><tbody>
                    {{range .Agents}}<tr>
                        <td><div style="font-weight:600;">{{.Name}}</div></td>
                        <td><span style="font-family:monospace;background:var(--bg-body);padding:2px 6px;border-radius:4px">{{.RemoteIP}}</span></td>
                        <td><span class="badge">运行正常</span><div id="agent-load-{{.Name}}" style="font-size:11px;color:var(--text-sub);margin-top:4px;font-family:monospace">{{if .SysStatus}}{{.SysStatus}}{{else}}Waiting...{{end}}</div></td>
                        <td><button class="btn-sm btn-del" onclick="delAgent('{{.Name}}')">🗑️ 卸载</button></td>
                    </tr>{{end}}
                    </tbody></table>
                    {{else}}<div style="text-align:center;padding:40px;color:var(--text-sub)">暂无在线节点</div>{{end}}
                </div>
            </div>
        </div>

        <div id="deploy" class="page">
            <div class="card">
                <h3>🛠️ 节点部署向导</h3>
                <div style="background:var(--bg-hover);padding:20px;border-radius:12px;border:1px solid var(--border)">
                    <p style="margin-top:0;font-size:14px;color:var(--text-sub)">在您的目标服务器上执行以下命令以安装 Agent。</p>
                    <div class="grid-form" style="margin-bottom:15px">
                        <div><label>节点名称</label><input id="agentName" placeholder="例如: HK-Node-1" value="Node-1"></div>
                        <div><label>连接地址类型</label><select id="addrType"><option value="domain">使用域名 (推荐)</option><option value="v4">使用 IPv4</option><option value="v6">使用 IPv6</option></select></div>
                    </div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap">
                        <button onclick="genCmd()">生成安装命令</button>
                        <button onclick="copyCmd()" class="btn-sec">📋 复制命令</button>
                    </div>
                    <div class="code-box"><pre id="cmdText">等待生成命令...</pre></div>
                </div>
            </div>
        </div>

        <div id="rules" class="page">
            <div class="card">
                <h3>➕ 新建转发规则</h3>
                <form action="/add" method="POST">
                    <div class="grid-form">
                        <div class="form-g"><label>备注名称</label><input name="note" placeholder="例如: 公司RDP" required></div>
                        <div class="form-g"><label>入口节点</label><select name="entry_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                        <div class="form-g"><label>入口端口</label><input type="number" name="entry_port" placeholder="1000-65535" required></div>
                        <div class="form-g"><label>出口节点</label><select name="exit_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                        <div class="form-g"><label>目标地址 (多IP用逗号分隔)</label><input name="target_ip" placeholder="例如: 1.2.3.4, 5.6.7.8" required></div>
                        <div class="form-g"><label>目标端口</label><input type="number" name="target_port" required></div>
                        
                        <div class="form-g"><label>流量限额 (GB)</label><input type="number" step="0.1" name="traffic_limit" value="0" placeholder="0为不限"></div>
                        <div class="form-g"><label>带宽限速 (MB/s)</label><input type="number" step="0.1" name="speed_limit" value="0" placeholder="0为不限"></div>
                        
                        <div class="form-g"><label>转发协议</label><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></div>
                        <div class="form-g" style="align-self:end"><button style="width:100%">立即创建</button></div>
                    </div>
                </form>
            </div>
            <div class="card">
                <h3>📜 规则列表</h3>
                <div class="table-responsive">
                    <table><thead><tr><th>备注 / 链路</th><th>目标地址 / 健康状态</th><th>监控 (在线 | 流量)</th><th>状态 / 限速</th><th>操作</th></tr></thead><tbody>
                    {{range .Rules}}
                    <tr style="{{if .Disabled}}opacity:0.6;filter:grayscale(100%);{{end}}">
                        <td>
                            <div style="font-weight:700;color:var(--text-main);font-size:15px">{{if .Note}}{{.Note}}{{else}}未命名规则{{end}}</div>
                            <div style="color:var(--text-sub);font-size:12px;margin-top:4px;display:flex;align-items:center;gap:4px">
                                <span style="background:var(--bg-body);padding:2px 6px;border-radius:4px">{{.EntryAgent}}:{{.EntryPort}}</span><span>➜</span><span style="background:var(--bg-body);padding:2px 6px;border-radius:4px">{{.ExitAgent}}</span>
                            </div>
                        </td>
                        <td style="color:var(--text-sub)">
                            <div style="font-family:monospace;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.TargetIP}}:{{.TargetPort}}">{{.TargetIP}}:{{.TargetPort}}</div>
                            <div style="font-size:11px;margin-top:4px;display:flex;align-items:center;gap:4px">
                                <span id="rule-status-dot-{{.ID}}" style="width:8px;height:8px;border-radius:50%;background:{{if .Disabled}}#ccc{{else}}var(--warning){{end}}"></span>
                                <span id="rule-latency-{{.ID}}" style="color:var(--text-sub)">检测中...</span>
                            </div>
                        </td>
                        <td style="min-width:200px">
                            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px"><span style="font-weight:600;color:var(--primary)">👥 <span id="rule-uc-{{.ID}}">{{.UserCount}}</span></span><span id="rule-traffic-{{.ID}}">{{formatBytes (add .TotalTx .TotalRx)}}</span></div>
                            {{if gt .TrafficLimit 0}}
                            <div class="prog-container"><div id="rule-bar-{{.ID}}" class="prog-bar" style="width:{{percent .TotalTx .TotalRx .TrafficLimit}}%; background:{{if ge (percent .TotalTx .TotalRx .TrafficLimit) 90.0}}var(--danger){{else}}var(--primary){{end}}"></div></div>
                            <div class="prog-limit"><span id="rule-limit-text-{{.ID}}">已用 {{percent .TotalTx .TotalRx .TrafficLimit | printf "%.1f"}}%</span><span>限额: {{formatBytes .TrafficLimit}}</span></div>
                            {{else}}
                            <div class="prog-container" style="background:var(--bg-body)"><div style="width:100%;background:var(--success);height:100%"></div></div><div class="prog-limit"><span>无限制</span></div>
                            {{end}}
                        </td>
                        <td>
                            <div style="margin-bottom:4px">
                                {{if .Disabled}}<span class="badge" style="background:var(--border);color:var(--text-sub)">已暂停</span>
                                {{else if and (gt .TrafficLimit 0) (ge (add .TotalTx .TotalRx) .TrafficLimit)}}<span class="badge danger">流量耗尽</span>
                                {{else}}<span class="badge">转发中</span>{{end}}
                            </div>
                            <div style="font-size:11px;color:var(--text-sub)">限速: {{formatSpeed .SpeedLimit}}</div>
                        </td>
                        <td>
                            <div style="display:flex;gap:8px">
                                <button class="btn-sm {{if .Disabled}}btn-sec{{end}}" style="{{if not .Disabled}}background:#10b981;{{end}}" onclick="toggleRule('{{.ID}}')">{{if .Disabled}}▶️{{else}}⏸{{end}}</button>
                                <button class="btn-sm btn-sec" onclick="openEdit('{{.ID}}','{{.Note}}','{{.EntryAgent}}','{{.EntryPort}}','{{.ExitAgent}}','{{.TargetIP}}','{{.TargetPort}}','{{.Protocol}}','{{.TrafficLimit}}','{{.SpeedLimit}}')">✎</button>
                                <button class="btn-sm btn-del" onclick="delRule('{{.ID}}')">🗑️</button>
                                <button class="btn-sm btn-sec" style="padding:6px" onclick="resetTraffic('{{.ID}}')" title="重置流量">🔄</button>
                            </div>
                        </td>
                    </tr>{{end}}
                    </tbody></table>
                </div>
            </div>
        </div>

        <div id="logs" class="page">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
                    <h3>🛡️ 系统操作日志 <span style="font-size:12px;color:var(--text-sub);font-weight:400;margin-left:10px">最近 200 条</span></h3>
                    <button class="btn-sec btn-sm" onclick="location.href='/export_logs'">📥 导出日志</button>
                </div>
                <div class="table-responsive">
                    <table><thead><tr><th>时间</th><th>操作来源 IP</th><th>动作类型</th><th>详情信息</th></tr></thead>
                    <tbody id="log-table-body">
                    {{range .Logs}}<tr>
                        <td style="color:var(--text-sub);font-family:monospace">{{.Time}}</td>
                        <td>{{.IP}}</td>
                        <td><span class="badge" style="background:var(--bg-body);color:var(--text-main)">{{.Action}}</span></td>
                        <td>{{.Msg}}</td>
                    </tr>{{end}}
                    </tbody></table>
                </div>
            </div>
        </div>

        <div id="settings" class="page">
            <div class="card" style="max-width:600px">
                <h3>⚙️ 系统设置</h3>
                <form action="/update_settings" method="POST">
                    <div style="display:grid;gap:20px">
                        <div class="form-g"><label>修改登录密码</label><input type="password" name="password" placeholder="留空则不修改"></div>
                        <div class="form-g"><label>Agent 通信 Token</label><input name="token" value="{{.Token}}"></div>
                        <div style="background:var(--bg-hover);padding:15px;border-radius:10px;border:1px solid var(--border)">
                            <div style="margin-bottom:10px;font-weight:600;font-size:14px">📢 Telegram 通知配置</div>
                            <div class="grid-form" style="grid-template-columns:1fr 1fr;gap:15px">
                                <div class="form-g"><label>Bot Token</label><input name="tg_bot_token" value="{{.Config.TgBotToken}}" placeholder="123456:ABC-DEF..."></div>
                                <div class="form-g"><label>Chat ID</label><input name="tg_chat_id" value="{{.Config.TgChatID}}" placeholder="-100xxxxxxx"></div>
                            </div>
                        </div>
                        <div class="form-g"><label>面板域名 (用于生成命令)</label><input name="master_domain" value="{{.MasterDomain}}" placeholder="例如: relay.example.com"></div>
                        <div class="grid-form" style="grid-template-columns:1fr 1fr;gap:20px">
                            <div class="form-g"><label>面板 IPv4</label><input name="master_ip" value="{{.MasterIP}}"></div>
                            <div class="form-g"><label>面板 IPv6</label><input name="master_ipv6" value="{{.MasterIPv6}}"></div>
                        </div>
                        <div style="display:flex;gap:15px">
                            <button style="flex:1">💾 保存配置</button>
                            <button type="button" class="btn-sec" style="flex:1" onclick="location.href='/download_config'">📂 导出备份</button>
                        </div>
                    </div>
                </form>
                <div style="margin-top:30px;padding-top:20px;border-top:1px solid var(--border);text-align:center">
                     <a href="/logout" style="color:var(--danger);text-decoration:none;font-size:14px;font-weight:600">退出登录</a>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="bottom-nav">
    <div class="nav-item active" onclick="nav('dashboard',this)"><div class="nav-icon">📊</div><div>概览</div></div>
    <div class="nav-item" onclick="nav('deploy',this)"><div class="nav-icon">🚀</div><div>部署</div></div>
    <div class="nav-item" onclick="nav('rules',this)"><div class="nav-icon">🔗</div><div>规则</div></div>
    <div class="nav-item" onclick="nav('logs',this)"><div class="nav-icon">🛡️</div><div>日志</div></div>
    <div class="nav-item" onclick="nav('settings',this)"><div class="nav-icon">⚙️</div><div>设置</div></div>
</div>

<div id="editModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeEdit()">&times;</span><h3>修改转发规则</h3>
        <form action="/edit" method="POST">
            <input type="hidden" name="id" id="e_id">
            <div class="grid-form">
                <div class="form-g"><label>备注名称</label><input name="note" id="e_note" required></div>
                <div class="form-g"><label>入口节点</label><select name="entry_agent" id="e_entry">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-g"><label>入口端口</label><input type="number" name="entry_port" id="e_eport" required></div>
                <div class="form-g"><label>出口节点</label><select name="exit_agent" id="e_exit">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-g"><label>目标地址 (多IP用逗号分隔)</label><input name="target_ip" id="e_tip" placeholder="例如: 1.2.3.4, 5.6.7.8" required></div>
                <div class="form-g"><label>目标端口</label><input type="number" name="target_port" id="e_tport" required></div>
                
                <div class="form-g"><label>流量限额 (GB)</label><input type="number" step="0.1" name="traffic_limit" id="e_limit"></div>
                <div class="form-g"><label>带宽限速 (MB/s)</label><input type="number" step="0.1" name="speed_limit" id="e_speed"></div>
                
                <div class="form-g"><label>协议</label><select name="protocol" id="e_proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select></div>
                <div class="form-g" style="grid-column: 1 / -1"><button style="width:100%">保存修改</button></div>
            </div>
        </form>
    </div>
</div>

<div id="confirmModal" class="modal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="confirm-modal-body">
            <div class="confirm-icon" id="c_icon">⚠️</div>
            <div class="confirm-title" id="c_title">确认操作</div>
            <div class="confirm-text" id="c_msg">您确定要继续吗？</div>
            <div class="confirm-actions"><button class="btn-sec" onclick="closeConfirm()">取消</button><button id="c_btn" class="btn-del">确认删除</button></div>
        </div>
    </div>
</div>

<script>
    var m_domain="{{.MasterDomain}}", m_v4="{{.MasterIP}}", m_v6="{{.MasterIPv6}}", port="9999", token="{{.Token}}", dwUrl="{{.DownloadURL}}";
    
    function nav(id, el) {
        window.location.hash = id;
        document.querySelectorAll('.page').forEach(e=>e.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        var titleMap = {'dashboard':'仪表盘', 'deploy':'节点部署', 'rules':'转发规则', 'settings':'系统设置', 'logs':'操作日志'};
        document.querySelector('.header-title').innerText = titleMap[id] || 'GoRelay';
        document.querySelectorAll('.sidebar .item').forEach(e => {
            if(e.onclick.toString().includes(id)) e.classList.add('active'); else e.classList.remove('active');
        });
        document.querySelectorAll('.bottom-nav .nav-item').forEach(e => {
            if(e.onclick.toString().includes(id)) e.classList.add('active'); else e.classList.remove('active');
        });
    }

    function toggleTheme() {
        const html = document.documentElement;
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    }
    const saved = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', saved);

    function showToast(msg, type) {
        var box = document.getElementById('toast');
        var icon = document.getElementById('t-icon');
        document.getElementById('t-msg').innerText = msg;
        if(msg.includes('✅') || msg.includes('📋')) icon.innerText = ''; else if(msg.includes('🚀')) icon.innerText = '';
        box.classList.add('show');
        if(type === 'warn') box.style.background = 'rgba(245, 158, 11, 0.9)'; else box.style.background = 'rgba(0,0,0,0.8)';
        setTimeout(() => { box.classList.remove('show'); }, 3000);
    }

    function showConfirm(title, msg, type, callback) {
        document.getElementById('c_title').innerText = title;
        document.getElementById('c_msg').innerHTML = msg; 
        const icon = document.getElementById('c_icon'); const btn = document.getElementById('c_btn');
        if (type === 'danger') { icon.innerText = '🚨'; btn.className = 'btn-del'; btn.innerText = '确认删除'; } 
        else { icon.innerText = '🤔'; btn.className = ''; btn.innerText = '确认'; }
        btn.onclick = function() { closeConfirm(); if(callback) callback(); };
        document.getElementById('confirmModal').style.display = 'block';
    }
    function closeConfirm() { document.getElementById('confirmModal').style.display = 'none'; }

    function genCmd() {
        var n = document.getElementById('agentName').value;
        var t = document.getElementById('addrType').value;
        var host = (t === "domain") ? (m_domain || location.hostname) : (t === "v4" ? m_v4 : '['+m_v6+']');
        if(!host || host === "[]") { alert("请在设置中配置 Master 地址"); return; }
        var cmd = 'curl -L -o /root/relay '+dwUrl+' && chmod +x /root/relay && /root/relay -service install -mode agent -name "'+n+'" -connect "'+host+':'+port+'" -token "'+token+'"';
        document.getElementById('cmdText').innerText = cmd;
    }
    
    function copyCmd() {
        var t = document.getElementById('cmdText').innerText;
        if (!t || t.indexOf("curl") === -1) { showToast('⚠️ 请先点击生成命令'); return; }
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(t).then(()=>showToast('✅ 命令已复制'), ()=>showToast('❌ 复制失败'));
        } else {
            try { var ta = document.createElement("textarea"); ta.value = t; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); showToast('✅ 命令已复制'); } catch (e) { showToast('❌ 复制失败'); }
        }
    }

    function delAgent(name) {
        showConfirm("卸载节点确认", "即将卸载节点 <b>"+name+"</b>。<br>此操作无法恢复。", "danger", function() {
            showToast('🚀 发送自毁指令...', 'warn');
            setTimeout(function(){ location.href = "/delete_agent?name=" + name; }, 800);
        });
    }

    function delRule(id) { showConfirm("删除规则确认", "确定删除此规则吗？<br>端口将立即停止转发。", "danger", function() { location.href = "/delete?id=" + id; }); }
    function toggleRule(id) { location.href = "/toggle?id=" + id; }
    function resetTraffic(id) { showConfirm("重置流量", "确定清零此规则的统计流量吗？", "normal", function() { location.href = "/reset_traffic?id=" + id; }); }

    function openEdit(id, note, entry, eport, exit, tip, tport, proto, limit, speed) {
        document.getElementById('e_id').value = id;
        document.getElementById('e_note').value = note;
        document.getElementById('e_entry').value = entry;
        document.getElementById('e_eport').value = eport;
        document.getElementById('e_exit').value = exit;
        document.getElementById('e_tip').value = tip;
        document.getElementById('e_tport').value = tport;
        document.getElementById('e_proto').value = proto;
        document.getElementById('e_limit').value = (parseFloat(limit) / (1024*1024*1024)).toFixed(2);
        document.getElementById('e_speed').value = (parseFloat(speed) / (1024*1024)).toFixed(1);
        document.getElementById('editModal').style.display = "block";
    }
    function closeEdit() { document.getElementById('editModal').style.display = "none"; }
    window.onclick = function(e) { if(e.target.className === 'modal') { closeEdit(); closeConfirm(); } }
    if(location.hash) { nav(location.hash.substring(1)); }
    
    function formatBytes(b) {
        const u = 1024;
        if (b < u) return b + " B";
        var div = u, exp = 0;
        while(b / u >= div) { div *= u; exp++; }
        return (b / div).toFixed(2) + " " + "KMGTPE"[exp] + "B";
    }

    var ctx = document.getElementById('trafficChart').getContext('2d');
    var chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(60).fill(''),
            datasets: [{ label: '实时速率', data: Array(60).fill(0), borderColor: '#6366f1', backgroundColor: 'rgba(99, 102, 241, 0.1)', borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
            scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: 'rgba(200, 200, 200, 0.1)' }, ticks: { callback: function(val) { return formatBytes(val) + '/s'; } } } },
            animation: { duration: 0 }
        }
    });

    function connectWS() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var ws = new WebSocket(proto + '//' + location.host + '/ws');
        ws.onmessage = function(event) {
            try {
                var msg = JSON.parse(event.data);
                if (msg.type === 'stats' && msg.data) {
                    var d = msg.data;
                    var totalEl = document.getElementById('stat-total-traffic'); if(totalEl) totalEl.innerText = formatBytes(d.total_traffic);
                    var speedEl = document.getElementById('current-speed'); if(speedEl) speedEl.innerText = formatBytes(d.current_speed) + '/s';

                    chart.data.datasets[0].data.push(d.current_speed);
                    chart.data.datasets[0].data.shift();
                    chart.update();

                    if(d.agents) { d.agents.forEach(function(a) { var el = document.getElementById('agent-load-' + a.name); if(el) el.innerText = a.sys_status; }); }
                    if(d.rules) {
                        d.rules.forEach(function(r) {
                            var trafEl = document.getElementById('rule-traffic-' + r.id); if(trafEl) trafEl.innerText = formatBytes(r.total);
                            var ucEl = document.getElementById('rule-uc-' + r.id); if(ucEl) ucEl.innerText = r.uc;
                            
                            var dot = document.getElementById('rule-status-dot-' + r.id);
                            var lat = document.getElementById('rule-latency-' + r.id);
                            if(dot && lat) {
                                if(r.status) {
                                    dot.style.background = '#10b981';
                                    lat.innerText = r.latency + ' ms';
                                    lat.style.color = 'var(--text-sub)';
                                } else {
                                    dot.style.background = '#ef4444';
                                    lat.innerText = '离线';
                                    lat.style.color = '#ef4444';
                                }
                            }

                            if(r.limit > 0) {
                                var pct = (r.total / r.limit) * 100; if(pct > 100) pct = 100;
                                var bar = document.getElementById('rule-bar-' + r.id); if(bar) { bar.style.width = pct + '%'; if(pct >= 90) bar.style.background = 'var(--danger)'; else bar.style.background = 'var(--primary)'; }
                                var txt = document.getElementById('rule-limit-text-' + r.id); if(txt) txt.innerText = '已用 ' + pct.toFixed(1) + '%';
                            }
                        });
                    }
                    if(d.logs && document.getElementById('logs').classList.contains('active')) {
                        var tbody = document.getElementById('log-table-body');
                        var html = '';
                        d.logs.forEach(function(l) {
                            html += '<tr><td style="color:var(--text-sub);font-family:monospace">' + l.time + '</td>' +
                                    '<td>' + l.ip + '</td>' +
                                    '<td><span class="badge" style="background:var(--bg-body);color:var(--text-main)">' + l.action + '</span></td>' +
                                    '<td>' + l.msg + '</td></tr>';
                        });
                        tbody.innerHTML = html;
                    }
                }
            } catch(e) {}
        };
        ws.onclose = function() { setTimeout(connectWS, 3000); };
    }
    connectWS();
</script>
</body>
</html>`
