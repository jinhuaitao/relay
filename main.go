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
	"net"
	"net/http"
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
)

// --- 配置与常量 ---

const (
	ConfigFile  = "config.json"
	ControlPort = ":9999"
	WebPort     = ":8888"
	DownloadURL = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/download/1.0/relay"

	// --- 性能调优 ---
	
	// TCP KeepAlive 探测间隔
	TCPKeepAlive = 60 * time.Second

	// UDP 缓冲区：4MB (平衡内存占用与抗丢包能力)
	UDPBufferSize = 4 * 1024 * 1024

	// 应用层拷贝缓冲区：32KB
	// 这是 Go 标准库 io.Copy 的默认大小，也是大多数 CPU L1 缓存的 sweet spot。
	// 既能保证吞吐量，又能保证流量统计的实时性平滑。
	CopyBufferSize = 32 * 1024
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

	TotalTx   int64 `json:"total_tx"`
	TotalRx   int64 `json:"total_rx"`
	UserCount int64 `json:"user_count"` // 在线用户数(独立IP)
}

type AppConfig struct {
	WebUser      string        `json:"web_user"`
	WebPass      string        `json:"web_pass"`
	AgentToken   string        `json:"agent_token"`
	MasterIP     string        `json:"master_ip"`
	MasterIPv6   string        `json:"master_ipv6"`
	MasterDomain string        `json:"master_domain"`
	IsSetup      bool          `json:"is_setup"`
	Rules        []LogicalRule `json:"saved_rules"`
}

type ForwardTask struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen"`
	Target   string `json:"target"`
}

type TrafficReport struct {
	TaskID    string `json:"task_id"`
	TxDelta   int64  `json:"tx"`
	RxDelta   int64  `json:"rx"`
	UserCount int64  `json:"uc"` // 上报独立IP数
}

type AgentInfo struct {
	Name     string   `json:"name"`
	RemoteIP string   `json:"remote_ip"`
	Conn     net.Conn `json:"-"`
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

// --- 全局变量 ---

var (
	config           AppConfig
	agents           = make(map[string]*AgentInfo)
	rules            = make([]LogicalRule, 0)
	mu               sync.Mutex
	runningListeners sync.Map
	activeTargets    sync.Map
	agentTraffic     sync.Map
	agentUserCounts  sync.Map // 记录每个任务的独立IP数
	sessions         = make(map[string]time.Time)
	configDirty      int32
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

// ================= 服务管理 =================

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
		}
		if isAlpine {
			exec.Command("rc-update", "del", "gorelay", "default").Run()
			exec.Command("rc-service", "gorelay", "stop").Run()
			os.Remove("/etc/init.d/gorelay")
		}
		log.Println("服务已卸载")
	}
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
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/setup", handleSetup)
	http.HandleFunc("/add", authMiddleware(handleAddRule))
	http.HandleFunc("/edit", authMiddleware(handleEditRule))
	http.HandleFunc("/delete", authMiddleware(handleDeleteRule))
	http.HandleFunc("/update_settings", authMiddleware(handleUpdateSettings))

	log.Printf("面板启动: http://localhost%s", WebPort)
	log.Fatal(http.ListenAndServe(WebPort, nil))
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
	agents[name] = &AgentInfo{Name: name, RemoteIP: remoteIP, Conn: conn}
	mu.Unlock()
	pushConfigToAll()

	for {
		var m Message
		if dec.Decode(&m) != nil {
			break
		}
		if m.Type == "stats" {
			handleStatsReport(m.Payload)
		}
	}
	mu.Lock()
	delete(agents, name)
	mu.Unlock()
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
					rules[i].UserCount = rep.UserCount // 更新在线人数

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

func pushConfigToAll() {
	mu.Lock()
	tasksMap := make(map[string][]ForwardTask)
	for _, r := range rules {
		if r.TrafficLimit > 0 && (r.TotalTx+r.TotalRx) >= r.TrafficLimit {
			continue
		}
		target := fmt.Sprintf("%s:%s", r.TargetIP, r.TargetPort)
		tasksMap[r.ExitAgent] = append(tasksMap[r.ExitAgent], ForwardTask{ID: r.ID + "_exit", Protocol: r.Protocol, Listen: ":" + r.BridgePort, Target: target})

		if exit, ok := agents[r.ExitAgent]; ok {
			rip := exit.RemoteIP
			if strings.Contains(rip, ":") && !strings.Contains(rip, "[") {
				rip = "[" + rip + "]"
			}
			tasksMap[r.EntryAgent] = append(tasksMap[r.EntryAgent], ForwardTask{ID: r.ID + "_entry", Protocol: r.Protocol, Listen: ":" + r.EntryPort, Target: fmt.Sprintf("%s:%s", rip, r.BridgePort)})
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
	mu.Unlock()

	data := struct {
		Agents       []AgentInfo
		Rules        []LogicalRule
		Token        string
		User         string
		DownloadURL  string
		TotalTraffic int64
		MasterIP     string
		MasterIPv6   string
		MasterDomain string
	}{al, displayRules, config.AgentToken, config.WebUser, DownloadURL, totalTraffic, config.MasterIP, config.MasterIPv6, config.MasterDomain}

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
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	t, _ := template.New("l").Parse(loginHtml)
	t.Execute(w, nil)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleAddRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	mu.Lock()
	rules = append(rules, LogicalRule{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Note:         r.FormValue("note"),
		EntryAgent:   r.FormValue("entry_agent"),
		EntryPort:    r.FormValue("entry_port"),
		ExitAgent:    r.FormValue("exit_agent"),
		TargetIP:     r.FormValue("target_ip"),
		TargetPort:   r.FormValue("target_port"),
		Protocol:     r.FormValue("protocol"),
		TrafficLimit: int64(limitGB * 1024 * 1024 * 1024),
		BridgePort:   fmt.Sprintf("%d", 20000+time.Now().UnixNano()%30000),
	})
	saveConfig()
	mu.Unlock()
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleEditRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	id := r.FormValue("id")
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)

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
			found = true
			break
		}
	}
	if found {
		saveConfig()
	}
	mu.Unlock()
	if found {
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
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
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
	saveConfig()
	mu.Unlock()
	http.Redirect(w, r, "/#settings", http.StatusSeeOther)
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
			defer t.Stop()
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
						json.NewEncoder(conn).Encode(Message{Type: "ping"})
					}
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
			if msg.Type == "update" {
				d, _ := json.Marshal(msg.Payload)
				var tasks []ForwardTask
				json.Unmarshal(d, &tasks)
				active := make(map[string]bool)

				for _, t := range tasks {
					active[t.ID] = true
					if lastTarget, loaded := activeTargets.Load(t.ID); loaded {
						if lastTarget.(string) != t.Target {
							if closeFunc, ok := runningListeners.Load(t.ID); ok {
								closeFunc.(func())()
								runningListeners.Delete(t.ID)
								agentTraffic.Delete(t.ID)
								agentUserCounts.Delete(t.ID)
								activeTargets.Delete(t.ID)
								time.Sleep(1 * time.Second)
							}
						}
					}
					if _, ok := runningListeners.Load(t.ID); ok {
						continue
					}
					agentTraffic.Store(t.ID, &TrafficCounter{})
					var uz int64 = 0
					agentUserCounts.Store(t.ID, &uz)
					activeTargets.Store(t.ID, t.Target)
					startProxy(t)
				}
				runningListeners.Range(func(k, v interface{}) bool {
					if !active[k.(string)] {
						v.(func())()
						runningListeners.Delete(k)
						agentTraffic.Delete(k)
						agentUserCounts.Delete(k)
						activeTargets.Delete(k)
					}
					return true
				})
			}
		}
		time.Sleep(3 * time.Second)
	}
}

// 辅助结构体：用于跟踪独立IP
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
				// 性能调优：让操作系统内核自动管理 TCP 窗口大小
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
					pipeTCP(conn, t.Target, t.ID)
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
				agentTraffic.Delete(t.ID)
				return
			}
			// UDP 仍然保持 4MB 缓冲区以防止突发丢包
			ln.SetReadBuffer(UDPBufferSize)
			ln.SetWriteBuffer(UDPBufferSize)
			l.Lock()
			closers = append(closers, func() { ln.Close() })
			l.Unlock()
			handleUDP(ln, t.Target, t.ID, ipTracker)
		}()
	}
}

func pipeTCP(src net.Conn, target, tid string) {
	defer src.Close()
	// 连接超时设为5秒
	dst, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer dst.Close()
	// 性能调优：让操作系统内核自动管理 TCP 窗口大小
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
	go copyCount(dst, src, &cnt.Tx)
	copyCount(src, dst, &cnt.Rx)
}

func handleUDP(ln *net.UDPConn, target, tid string, tracker *IpTracker) {
	udpSessions := &sync.Map{}
	defer func() {
		udpSessions.Range(func(key, value interface{}) bool {
			value.(*udpSession).conn.Close()
			return true
		})
	}()
	dstAddr, _ := net.ResolveUDPAddr("udp", target)
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
				if now.Sub(s.lastActive) > 60*time.Second {
					s.conn.Close()
					udpSessions.Delete(key)
					tracker.Remove(key.(string)) // UDP会话超时移除IP
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
			newConn, err := net.DialUDP("udp", nil, dstAddr)
			if err != nil {
				continue
			}
			s := &udpSession{conn: newConn, lastActive: time.Now()}
			udpSessions.Store(sAddr, s)
			tracker.Add(sAddr) // 新UDP会话增加IP
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
						tracker.Remove(k) // 异常关闭移除IP
						break
					}
					ln.WriteToUDP(b[:m], sa)
					atomic.AddInt64(&cnt.Rx, int64(m))
				}
			}(newConn, srcAddr, sAddr)
		}
	}
}

// --- 核心优化：标准拷贝函数 (恢复实时统计) ---

func copyCount(dst io.Writer, src io.Reader, c *int64) {
	// 获取缓冲区
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	// 使用带缓冲的 Copy，确保每次读写的数据量适中 (32KB-64KB)
	// 这样既能保证性能，又能让 CounterWriter.Write 被频繁调用，从而实时更新统计
	cw := &CounterWriter{Writer: dst, Counter: c}
	io.CopyBuffer(cw, src, buf)
}

// --- 计数器 (仅保留 Write 以支持实时统计) ---

type CounterWriter struct {
	io.Writer
	Counter *int64
}

// Write 实现标准 io.Writer 接口
// 每次数据包传输 (比如 32KB) 都会触发此函数，从而实时增加流量计数
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
	}
}

func saveConfig() {
	config.Rules = rules
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

const setupHtml = `<!DOCTYPE html><html><head><title>GoRelay Setup</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#f3f4f6;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.card{background:#fff;padding:40px;border-radius:16px;box-shadow:0 10px 15px -3px rgba(0,0,0,0.1);width:100%;max-width:360px}h2{text-align:center;color:#111827;margin-bottom:30px;font-weight:700}label{display:block;margin-bottom:8px;color:#374151;font-size:14px;font-weight:500}input{width:100%;padding:12px;border:1px solid #d1d5db;border-radius:8px;box-sizing:border-box;font-size:14px;transition:0.2s;margin-bottom:20px;outline:none}input:focus{border-color:#4f46e5;box-shadow:0 0 0 3px rgba(79, 70, 229, 0.1)}button{width:100%;padding:12px;background:#4f46e5;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:0.2s}button:hover{background:#4338ca}</style></head><body><form class="card" method="POST"><h2>初始化配置</h2><label>管理员账号</label><input name="username" required><label>管理员密码</label><input type="password" name="password" required><label>Agent 通信 Token</label><input name="token" required><button>启动服务</button></form></body></html>`

const loginHtml = `<!DOCTYPE html><html><head><title>GoRelay Login</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#f3f4f6;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.card{background:#fff;padding:40px;border-radius:16px;box-shadow:0 10px 15px -3px rgba(0,0,0,0.1);width:100%;max-width:350px}h2{text-align:center;color:#111827;margin-bottom:30px;font-weight:700}input{width:100%;padding:13px;border:1px solid #d1d5db;border-radius:8px;box-sizing:border-box;font-size:15px;margin-bottom:20px;transition:all .2s;outline:none}input:focus{border-color:#4f46e5;box-shadow:0 0 0 3px rgba(79, 70, 229, 0.1)}button{width:100%;padding:13px;background:#4f46e5;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}button:hover{background:#4338ca}</style></head><body><form class="card" method="POST"><h2>登录面板</h2><input name="username" placeholder="账号" required><input type="password" name="password" placeholder="密码" required><button>登 录</button></form></body></html>`

const dashboardHtml = `
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8"><title>GoRelay Pro</title>
<style>
:root{--w:240px;--primary:#4f46e5;--bg:#f3f4f6;--text:#1f2937;--border:#e5e7eb}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;height:100vh;background:var(--bg);color:var(--text)}
.sidebar{width:var(--w);background:#111827;color:#fff;display:flex;flex-direction:column;flex-shrink:0}
.brand{padding:24px;font-size:20px;font-weight:700;color:#fff;border-bottom:1px solid #1f2937;display:flex;align-items:center;gap:10px}
.menu{flex:1;padding:20px 10px;display:flex;flex-direction:column;gap:5px}
.item{display:flex;align-items:center;padding:12px 16px;color:#9ca3af;text-decoration:none;cursor:pointer;border-radius:8px;transition:all .2s;font-size:14px;font-weight:500}
.item:hover{background:#1f2937;color:#fff}
.item.active{background:var(--primary);color:#fff}
.icon{margin-right:12px;font-size:18px}
.user{padding:20px;border-top:1px solid #1f2937;background:#0f1521}
.user-info{font-size:14px;font-weight:600;margin-bottom:8px;color:#fff}
.logout{display:block;text-align:center;background:#dc2626;color:#fff;text-decoration:none;padding:8px;border-radius:6px;font-size:12px;transition:.2s}
.logout:hover{background:#b91c1c}
.main{flex:1;padding:30px;overflow-y:auto;overflow-x:hidden}
.page{display:none;animation:fadeIn .3s ease-out}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);margin-bottom:24px;border:1px solid var(--border)}
h3{margin-top:0;margin-bottom:20px;font-size:18px;color:#111827;font-weight:700}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:24px;margin-bottom:24px}
.stat-card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);display:flex;align-items:center;justify-content:space-between;border:1px solid var(--border)}
.stat-info .val{font-size:28px;font-weight:800;color:#111827;line-height:1.2}
.stat-info .lbl{color:#6b7280;font-size:13px;font-weight:500;margin-top:4px}
.stat-icon{width:48px;height:48px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:24px}
table{width:100%;border-collapse:separate;border-spacing:0}
th{text-align:left;padding:12px 16px;color:#6b7280;font-size:12px;font-weight:600;background:#f9fafb;border-bottom:1px solid var(--border)}
td{padding:16px;border-bottom:1px solid var(--border);font-size:14px;color:#374151}
tr:hover td{background:#f9fafb}
.badge{padding:4px 10px;border-radius:99px;font-size:12px;font-weight:600;background:#d1fae5;color:#065f46;display:inline-block}
.badge-danger{background:#fee2e2;color:#991b1b}
input,select{padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;width:100%;box-sizing:border-box;font-size:14px;transition:.2s;outline:none}
input:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(79, 70, 229, 0.1)}
button{background:var(--primary);color:#fff;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500;transition:.2s}
button:hover{background:#4338ca;transform:translateY(-1px)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-del{background:#fff;border:1px solid #e5e7eb;color:#dc2626}
.btn-del:hover{background:#fee2e2;border-color:#fecaca}
.form-g{margin-bottom:15px}label{display:block;font-size:13px;font-weight:500;margin-bottom:6px;color:#374151}
.grid-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;align-items:end}
.prog-container{width:100%;background:#e5e7eb;border-radius:99px;height:8px;margin-top:8px;overflow:hidden}
.prog-bar{height:100%;background:var(--primary);border-radius:99px;transition:width .4s ease}
.prog-limit{font-size:12px;color:#6b7280;margin-top:4px;display:flex;justify-content:space-between}
.modal{display:none;position:fixed;z-index:999;left:0;top:0;width:100%;height:100%;background-color:rgba(0,0,0,0.5);backdrop-filter:blur(2px)}
.modal-content{background:#fff;margin:5vh auto;padding:30px;border-radius:16px;width:90%;max-width:550px;position:relative;box-shadow:0 20px 25px -5px rgba(0,0,0,0.1)}
.close{position:absolute;right:20px;top:20px;font-size:24px;cursor:pointer;color:#9ca3af;transition:.2s}
.close:hover{color:#111827}
pre{background:#111827;color:#e5e7eb;padding:20px;border-radius:8px;font-family:monospace;font-size:13px;line-height:1.6;overflow-x:auto;border:1px solid #374151}
</style>
</head>
<body>
<div class="sidebar">
    <div class="brand">🚀 GoRelay Pro</div>
    <div class="menu">
        <a class="item active" onclick="nav('dashboard',this)"><span class="icon">📊</span> 仪表盘</a>
        <a class="item" onclick="nav('deploy',this)"><span class="icon">⚡</span> 节点部署</a>
        <a class="item" onclick="nav('rules',this)"><span class="icon">🔗</span> 转发规则</a>
        <a class="item" onclick="nav('settings',this)"><span class="icon">⚙️</span> 系统设置</a>
    </div>
    <div class="user">
        <div class="user-info">👤 {{.User}}</div>
        <a href="/logout" class="logout">安全退出</a>
    </div>
</div>
<div class="main">
    <div id="dashboard" class="page active">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-info"><div class="val">{{formatBytes .TotalTraffic}}</div><div class="lbl">累计消耗流量</div></div>
                <div class="stat-icon" style="background:#e0e7ff;color:#4f46e5">📶</div>
            </div>
            <div class="stat-card">
                <div class="stat-info"><div class="val">{{len .Agents}}</div><div class="lbl">在线节点数量</div></div>
                <div class="stat-icon" style="background:#dcfce7;color:#16a34a">📡</div>
            </div>
            <div class="stat-card">
                <div class="stat-info"><div class="val">{{len .Rules}}</div><div class="lbl">规则总数</div></div>
                <div class="stat-icon" style="background:#fef3c7;color:#d97706">⚡</div>
            </div>
        </div>
        <div class="card">
            <h3>节点状态监控</h3>
            {{if .Agents}}
            <table><thead><tr><th>节点名称</th><th>IP 地址</th><th>连接状态</th></tr></thead><tbody>
            {{range .Agents}}<tr><td><b>{{.Name}}</b></td><td>{{.RemoteIP}}</td><td><span class="badge">运行正常</span></td></tr>{{end}}
            </tbody></table>
            {{else}}<div style="text-align:center;padding:40px;color:#9ca3af">暂无在线节点</div>{{end}}
        </div>
    </div>
    <div id="deploy" class="page">
        <div class="card">
            <h3>节点部署向导</h3>
            <div style="background:#f9fafb;padding:20px;border-radius:8px;border:1px solid #e5e7eb">
                <div style="display:flex;gap:10px;margin-bottom:15px;align-items:end">
                    <div style="flex:1"><label>节点名称</label><input id="agentName" placeholder="例如: HK-Node-1" value="Node-1"></div>
                    <div style="flex:1"><label>连接地址类型</label><select id="addrType"><option value="domain">使用域名 (推荐)</option><option value="v4">使用 IPv4</option><option value="v6">使用 IPv6</option></select></div>
                    <div><button onclick="genCmd()">生成安装命令</button></div>
                    <div><button onclick="copyCmd()" style="background:#fff;border:1px solid #d1d5db;color:#374151">📋 复制</button></div>
                </div>
                <pre id="cmdText">等待生成命令...</pre>
                <div style="margin-top:10px;font-size:12px;color:#6b7280">提示：请在被控机 root 权限下执行此命令。</div>
            </div>
        </div>
    </div>
    <div id="rules" class="page">
        <div class="card">
            <h3>新建转发规则</h3>
            <form action="/add" method="POST">
                <div class="grid-form">
                    <div class="form-g"><label>备注名称</label><input name="note" placeholder="例如: 公司RDP" required></div>
                    <div class="form-g"><label>入口节点</label><select name="entry_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                    <div class="form-g"><label>入口端口</label><input type="number" name="entry_port" placeholder="1000-65535" required></div>
                    <div class="form-g"><label>出口节点</label><select name="exit_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                    <div class="form-g"><label>目标地址 (IP/域名)</label><input name="target_ip" required></div>
                    <div class="form-g"><label>目标端口</label><input type="number" name="target_port" required></div>
                    <div class="form-g"><label>流量限制 (GB)</label><input type="number" step="0.1" name="traffic_limit" value="0"></div>
                    <div class="form-g"><label>转发协议</label><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></div>
                    <div class="form-g"><button>立即创建</button></div>
                </div>
            </form>
        </div>
        <div class="card">
            <h3>规则列表</h3>
            <table><thead><tr><th>备注 / 链路</th><th>目标</th><th>监控 (在线人数 | 流量)</th><th>状态</th><th>操作</th></tr></thead><tbody>
            {{range .Rules}}
            <tr>
                <td>
                    <div style="font-weight:600;color:#111827">{{if .Note}}{{.Note}}{{else}}未命名规则{{end}}</div>
                    <div style="color:#6b7280;font-size:12px;margin-top:2px">{{.EntryAgent}}:{{.EntryPort}} ➜ {{.ExitAgent}}</div>
                </td>
                <td style="color:#4b5563">{{.TargetIP}}:{{.TargetPort}}</td>
                <td style="width:240px">
                    <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:2px">
                        <span style="font-weight:600;color:#4f46e5">👥 {{.UserCount}} 人在线</span>
                        <span>{{formatBytes (add .TotalTx .TotalRx)}} 用量</span>
                    </div>
                    {{if gt .TrafficLimit 0}}
                    <div class="prog-container">
                        <div class="prog-bar" style="width:{{percent .TotalTx .TotalRx .TrafficLimit}}%; background:{{if ge (percent .TotalTx .TotalRx .TrafficLimit) 90.0}}#dc2626{{else}}#4f46e5{{end}}"></div>
                    </div>
                    <div class="prog-limit"><span>限额: {{formatBytes .TrafficLimit}}</span></div>
                    {{else}}
                    <div class="prog-container" style="background:#f3f4f6"><div style="width:100%;background:#10b981;height:100%"></div></div>
                    {{end}}
                </td>
                <td>
                    {{if and (gt .TrafficLimit 0) (ge (add .TotalTx .TotalRx) .TrafficLimit)}}
                    <span class="badge badge-danger">流量耗尽</span>
                    {{else}}
                    <span class="badge">转发中</span>
                    {{end}}
                </td>
                <td>
                    <div style="display:flex;gap:5px">
                        <button class="btn-sm" style="background:#fff;border:1px solid #d1d5db;color:#374151" onclick="openEdit('{{.ID}}','{{.Note}}','{{.EntryAgent}}','{{.EntryPort}}','{{.ExitAgent}}','{{.TargetIP}}','{{.TargetPort}}','{{.Protocol}}','{{.TrafficLimit}}')">编辑</button>
                        <a href="/delete?id={{.ID}}" class="btn-del" style="padding:5px 10px;border-radius:6px;text-decoration:none;font-size:12px" onclick="return confirm('确定删除？')">🗑️</a>
                    </div>
                </td>
            </tr>
            {{end}}
            </tbody></table>
        </div>
    </div>
    <div id="settings" class="page">
        <div class="card" style="max-width:500px">
            <h3>系统设置</h3>
            <form action="/update_settings" method="POST">
                <div class="form-g"><label>修改登录密码</label><input type="password" name="password" placeholder="留空则不修改"></div>
                <div class="form-g"><label>Agent 通信 Token</label><input name="token" value="{{.Token}}"></div>
                <div class="form-g"><label>面板域名 (生成命令用)</label><input name="master_domain" value="{{.MasterDomain}}"></div>
                <div class="form-g"><label>面板 IPv4</label><input name="master_ip" value="{{.MasterIP}}"></div>
                <div class="form-g"><label>面板 IPv6</label><input name="master_ipv6" value="{{.MasterIPv6}}"></div>
                <button>保存配置</button>
            </form>
        </div>
    </div>
</div>
<div id="editModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeEdit()">&times;</span>
        <h3>修改转发规则</h3>
        <form action="/edit" method="POST">
            <input type="hidden" name="id" id="e_id">
            <div class="grid-form">
                <div class="form-g"><label>备注名称</label><input name="note" id="e_note" required></div>
                <div class="form-g"><label>入口节点</label><select name="entry_agent" id="e_entry">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-g"><label>入口端口</label><input type="number" name="entry_port" id="e_eport" required></div>
                <div class="form-g"><label>出口节点</label><select name="exit_agent" id="e_exit">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                <div class="form-g"><label>目标地址</label><input name="target_ip" id="e_tip" required></div>
                <div class="form-g"><label>目标端口</label><input type="number" name="target_port" id="e_tport" required></div>
                <div class="form-g"><label>流量限制 (GB)</label><input type="number" step="0.1" name="traffic_limit" id="e_limit"></div>
                <div class="form-g"><label>协议</label><select name="protocol" id="e_proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select></div>
                <div class="form-g"><button>保存修改</button></div>
            </div>
        </form>
    </div>
</div>
<script>
    var m_domain="{{.MasterDomain}}", m_v4="{{.MasterIP}}", m_v6="{{.MasterIPv6}}", port="9999", token="{{.Token}}", dwUrl="{{.DownloadURL}}";
    function nav(id, el) {
        window.location.hash = id;
        document.querySelectorAll('.page').forEach(e=>e.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        document.querySelectorAll('.item').forEach(e=>e.classList.remove('active')); 
        if(el) el.classList.add('active');
    }
    function genCmd() {
        var n = document.getElementById('agentName').value;
        var t = document.getElementById('addrType').value;
        var host = (t === "domain") ? (m_domain || location.hostname) : (t === "v4" ? m_v4 : '['+m_v6+']');
        if(!host || host === "[]") { alert("请在设置中配置Master地址"); return; }
        var cmd = 'curl -L -o /root/relay '+dwUrl+' && chmod +x /root/relay && /root/relay -service install -mode agent -name "'+n+'" -connect "'+host+':'+port+'" -token "'+token+'"';
        document.getElementById('cmdText').innerText = cmd;
    }
    function copyCmd() {
        var t = document.getElementById('cmdText').innerText;
        if (!t || t.indexOf("curl") === -1) { alert('请先生成命令'); return; }
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(t).then(() => alert('复制成功'));
        } else {
            var ta = document.createElement("textarea");
            ta.value = t;
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); alert('复制成功'); } catch (e) { alert('复制失败'); }
            document.body.removeChild(ta);
        }
    }
    function openEdit(id, note, entry, eport, exit, tip, tport, proto, limit) {
        document.getElementById('e_id').value = id;
        document.getElementById('e_note').value = note;
        document.getElementById('e_entry').value = entry;
        document.getElementById('e_eport').value = eport;
        document.getElementById('e_exit').value = exit;
        document.getElementById('e_tip').value = tip;
        document.getElementById('e_tport').value = tport;
        document.getElementById('e_proto').value = proto;
        document.getElementById('e_limit').value = (parseFloat(limit) / (1024*1024*1024)).toFixed(2);
        document.getElementById('editModal').style.display = "block";
    }
    function closeEdit() { document.getElementById('editModal').style.display = "none"; }
    window.onclick = function(e) { if(e.target.className === 'modal') closeEdit(); }
    if(location.hash) nav(location.hash.substring(1));
    setInterval(() => { 
        if(document.querySelector('.page.active').id === 'dashboard' && document.activeElement.tagName !== 'INPUT') location.reload(); 
    }, 10000);
</script></body></html>`
