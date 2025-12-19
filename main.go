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
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- 配置与常量 ---

const (
	ConfigFile  = "config.json"
	ControlPort = ":9999" // Agent 连接端口
	WebPort     = ":8888" // 网页管理端口
	DownloadURL = "https://github.com/jinhuaitao/relay/releases/download/1.0/relay"
	UDPTimeout  = 60 * time.Second // UDP会话超时时间
)

// --- 数据结构 ---

type AppConfig struct {
	WebUser    string `json:"web_user"`
	WebPass    string `json:"web_pass"`
	AgentToken string `json:"agent_token"`
	IsSetup    bool   `json:"is_setup"`
}

type ForwardTask struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"` // tcp, udp, both
	Listen   string `json:"listen"`
	Target   string `json:"target"`
}

type TrafficReport struct {
	TaskID  string `json:"task_id"`
	TxDelta int64  `json:"tx"`
	RxDelta int64  `json:"rx"`
}

type LogicalRule struct {
	ID         string `json:"id"`
	EntryAgent string `json:"entry_agent"`
	EntryPort  string `json:"entry_port"`
	ExitAgent  string `json:"exit_agent"`
	TargetIP   string `json:"target_ip"`
	TargetPort string `json:"target_port"`
	Protocol   string `json:"protocol"`
	BridgePort string `json:"bridge_port"`
	
	TotalTx int64 `json:"-"`
	TotalRx int64 `json:"-"`
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

// --- 全局变量 ---

var (
	config           AppConfig
	agents           = make(map[string]*AgentInfo)
	rules            = make([]LogicalRule, 0)
	mu               sync.Mutex
	runningListeners sync.Map 
	agentTraffic     sync.Map 
	sessions         = make(map[string]time.Time)
)

// --- 主程序 ---

func main() {
	mode := flag.String("mode", "master", "运行模式")
	name := flag.String("name", "", "Agent名称")
	connect := flag.String("connect", "", "Master地址")
	token := flag.String("token", "", "通信Token")
	flag.Parse()
	setupSignalHandler()

	if *mode == "master" {
		loadConfig()
		runMaster()
	} else if *mode == "agent" {
		if *name == "" || *connect == "" || *token == "" {
			log.Fatal("参数不足")
		}
		runAgent(*name, *connect, *token)
	} else {
		log.Fatal("未知模式")
	}
}

// ================= MASTER =================

func runMaster() {
	go func() {
		ln, err := net.Listen("tcp", ControlPort)
		if err != nil { log.Fatal(err) }
		for {
			c, err := ln.Accept()
			if err == nil { go handleAgentConn(c) }
		}
	}()

	http.HandleFunc("/", authMiddleware(handleDashboard))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/setup", handleSetup)
	http.HandleFunc("/add", authMiddleware(handleAddRule))
	http.HandleFunc("/delete", authMiddleware(handleDeleteRule))
	http.HandleFunc("/update_settings", authMiddleware(handleUpdateSettings))

	log.Printf("面板启动: http://localhost%s", WebPort)
	log.Fatal(http.ListenAndServe(WebPort, nil))
}

func handleAgentConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	var msg Message
	if dec.Decode(&msg) != nil || msg.Type != "auth" { return }
	
	data := msg.Payload.(map[string]interface{})
	if data["token"].(string) != config.AgentToken { return }
	
	name := data["name"].(string)
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	
	mu.Lock(); agents[name] = &AgentInfo{Name: name, RemoteIP: remoteIP, Conn: conn}; mu.Unlock()
	pushConfigToAll()
	
	for {
		var m Message
		if dec.Decode(&m) != nil { break }
		if m.Type == "stats" { handleStatsReport(m.Payload) }
	}
	mu.Lock(); delete(agents, name); mu.Unlock()
}

func handleStatsReport(payload interface{}) {
	d, _ := json.Marshal(payload)
	var reports []TrafficReport
	json.Unmarshal(d, &reports)
	mu.Lock()
	defer mu.Unlock()
	for _, rep := range reports {
		if strings.HasSuffix(rep.TaskID, "_entry") {
			rid := strings.TrimSuffix(rep.TaskID, "_entry")
			for i := range rules {
				if rules[i].ID == rid {
					rules[i].TotalTx += rep.TxDelta
					rules[i].TotalRx += rep.RxDelta
					break
				}
			}
		}
	}
}

func pushConfigToAll() {
	mu.Lock()
	defer mu.Unlock()
	tasks := make(map[string][]ForwardTask)
	for _, r := range rules {
		target := fmt.Sprintf("%s:%s", r.TargetIP, r.TargetPort)
		tasks[r.ExitAgent] = append(tasks[r.ExitAgent], ForwardTask{ID: r.ID+"_exit", Protocol: r.Protocol, Listen: ":"+r.BridgePort, Target: target})
		if exit, ok := agents[r.ExitAgent]; ok {
			// 处理 IPv6 地址加括号
			rip := exit.RemoteIP
			if strings.Contains(rip, ":") && !strings.Contains(rip, "[") { rip = "[" + rip + "]" }
			tasks[r.EntryAgent] = append(tasks[r.EntryAgent], ForwardTask{ID: r.ID+"_entry", Protocol: r.Protocol, Listen: ":"+r.EntryPort, Target: fmt.Sprintf("%s:%s", rip, r.BridgePort)})
		}
	}
	for n, a := range agents {
		t := tasks[n]; if t == nil { t = []ForwardTask{} }
		json.NewEncoder(a.Conn).Encode(Message{Type: "update", Payload: t})
	}
}

// ================= WEB HANDLERS =================

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	
	al := make([]AgentInfo, 0)
	for _, a := range agents { al = append(al, *a) }
	
	var totalTraffic int64
	for _, r := range rules { totalTraffic += (r.TotalTx + r.TotalRx) }

	data := struct {
		Agents []AgentInfo; Rules []LogicalRule; Token string; User string; DownloadURL string
		TotalTraffic int64
	}{ al, rules, config.AgentToken, config.WebUser, DownloadURL, totalTraffic }
	
	t := template.New("dash").Funcs(template.FuncMap{"formatBytes": formatBytes})
	t, _ = t.Parse(dashboardHtml)
	t.Execute(w, data)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock(); setup := config.IsSetup; mu.Unlock()
		if !setup { http.Redirect(w, r, "/setup", http.StatusSeeOther); return }
		c, err := r.Cookie("sid")
		if err != nil { http.Redirect(w, r, "/login", http.StatusSeeOther); return }
		mu.Lock(); exp, ok := sessions[c.Value]; mu.Unlock()
		if !ok || time.Now().After(exp) { http.Redirect(w, r, "/login", http.StatusSeeOther); return }
		mu.Lock(); sessions[c.Value] = time.Now().Add(1*time.Hour); mu.Unlock()
		next(w, r)
	}
}
func handleSetup(w http.ResponseWriter, r *http.Request) {
	mu.Lock(); setup := config.IsSetup; mu.Unlock()
	if setup { http.Redirect(w, r, "/", http.StatusSeeOther); return }
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
		mu.Lock(); u, p := config.WebUser, config.WebPass; mu.Unlock()
		if r.FormValue("username") == u && md5Hash(r.FormValue("password")) == p {
			sid := make([]byte, 16); rand.Read(sid); sidStr := hex.EncodeToString(sid)
			mu.Lock(); sessions[sidStr] = time.Now().Add(1*time.Hour); mu.Unlock()
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
	if r.Method!="POST" { return }
	mu.Lock()
	rules = append(rules, LogicalRule{
		ID: fmt.Sprintf("%d", time.Now().UnixNano()),
		EntryAgent: r.FormValue("entry_agent"), EntryPort: r.FormValue("entry_port"),
		ExitAgent: r.FormValue("exit_agent"), TargetIP: r.FormValue("target_ip"), TargetPort: r.FormValue("target_port"),
		Protocol: r.FormValue("protocol"), BridgePort: fmt.Sprintf("%d", 20000+time.Now().UnixNano()%30000),
	})
	mu.Unlock()
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}
func handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	var nr []LogicalRule; for _,x := range rules { if x.ID != id { nr = append(nr, x) } }
	rules = nr; mu.Unlock(); go pushConfigToAll(); http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}
func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method!="POST" { return }
	mu.Lock()
	if p := r.FormValue("password"); p!="" { config.WebPass = md5Hash(p) }
	if t := r.FormValue("token"); t!="" { config.AgentToken = t }
	saveConfig(); mu.Unlock()
	http.Redirect(w, r, "/#settings", http.StatusSeeOther)
}

// ================= AGENT =================

func runAgent(name, masterAddr, token string) {
	for {
		conn, err := net.Dial("tcp", masterAddr)
		if err != nil { time.Sleep(5 * time.Second); continue }
		json.NewEncoder(conn).Encode(Message{Type: "auth", Payload: map[string]string{"name": name, "token": token}})
		
		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop: return
				case <-t.C:
					var reps []TrafficReport
					agentTraffic.Range(func(k, v interface{}) bool {
						c := v.(*TrafficCounter)
						tx, rx := atomic.SwapInt64(&c.Tx, 0), atomic.SwapInt64(&c.Rx, 0)
						if tx>0 || rx>0 { reps = append(reps, TrafficReport{TaskID: k.(string), TxDelta: tx, RxDelta: rx}) }
						return true
					})
					if len(reps)>0 { json.NewEncoder(conn).Encode(Message{Type: "stats", Payload: reps}) } else { json.NewEncoder(conn).Encode(Message{Type: "ping"}) }
				}
			}
		}()

		dec := json.NewDecoder(conn)
		for {
			var msg Message; if dec.Decode(&msg) != nil { close(stop); conn.Close(); break }
			if msg.Type == "update" {
				d, _ := json.Marshal(msg.Payload); var tasks []ForwardTask; json.Unmarshal(d, &tasks)
				active := make(map[string]bool)
				for _, t := range tasks {
					active[t.ID] = true
					if _, ok := runningListeners.Load(t.ID); ok { continue }
					agentTraffic.Store(t.ID, &TrafficCounter{})
					startProxy(t)
				}
				runningListeners.Range(func(k, v interface{}) bool {
					if !active[k.(string)] { v.(func())(); runningListeners.Delete(k); agentTraffic.Delete(k) }
					return true
				})
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func startProxy(t ForwardTask) {
	var closers []func(); var l sync.Mutex; closed := false
	closeAll := func() { l.Lock(); defer l.Unlock(); if closed { return }; closed=true; for _, f := range closers { f() } }
	runningListeners.Store(t.ID, closeAll)

	if t.Protocol == "tcp" || t.Protocol == "both" {
		go func() {
			ln, err := net.Listen("tcp", t.Listen); if err!=nil { return }
			l.Lock(); closers=append(closers, func(){ ln.Close() }); l.Unlock()
			for { c,e := ln.Accept(); if e!=nil {break}; go pipeTCP(c, t.Target, t.ID) }
		}()
	}
	if t.Protocol == "udp" || t.Protocol == "both" {
		go func() {
			addr, _ := net.ResolveUDPAddr("udp", t.Listen); ln, err := net.ListenUDP("udp", addr); if err!=nil {return}
			l.Lock(); closers=append(closers, func(){ ln.Close() }); l.Unlock()
			handleUDP(ln, t.Target, t.ID)
		}()
	}
}

func pipeTCP(src net.Conn, target, tid string) {
	defer src.Close(); dst, err := net.DialTimeout("tcp", target, 5*time.Second); if err!=nil {return}; defer dst.Close()
	v, _ := agentTraffic.Load(tid); cnt := v.(*TrafficCounter)
	go copyCount(dst, src, &cnt.Tx); copyCount(src, dst, &cnt.Rx)
}

// UDP 核心升级：会话管理
func handleUDP(ln *net.UDPConn, target, tid string) {
	// 简单的内存会话表：SourceAddr -> RemoteConn
	sessions := make(map[string]*net.UDPConn)
	// 最后活跃时间
	lastActive := make(map[string]time.Time)
	var sl sync.Mutex

	dstAddr, _ := net.ResolveUDPAddr("udp", target)
	v, _ := agentTraffic.Load(tid); cnt := v.(*TrafficCounter)
	buf := make([]byte, 4096)

	// 定时清理过期会话
	go func() {
		for {
			time.Sleep(10 * time.Second)
			sl.Lock()
			now := time.Now()
			for k, t := range lastActive {
				if now.Sub(t) > UDPTimeout {
					if conn, ok := sessions[k]; ok { conn.Close() }
					delete(sessions, k)
					delete(lastActive, k)
				}
			}
			sl.Unlock()
		}
	}()

	for {
		n, srcAddr, err := ln.ReadFromUDP(buf)
		if err != nil { break }
		atomic.AddInt64(&cnt.Tx, int64(n))

		sAddr := srcAddr.String()
		sl.Lock()
		conn, exists := sessions[sAddr]
		lastActive[sAddr] = time.Now()
		sl.Unlock()

		if exists {
			conn.Write(buf[:n])
		} else {
			// 建立新会话
			newConn, err := net.DialUDP("udp", nil, dstAddr)
			if err != nil { continue }
			
			sl.Lock()
			sessions[sAddr] = newConn
			sl.Unlock()
			
			newConn.Write(buf[:n])

			// 异步读取回包
			go func(c *net.UDPConn, sa *net.UDPAddr) {
				b := make([]byte, 4096)
				for {
					c.SetReadDeadline(time.Now().Add(UDPTimeout))
					m, _, e := c.ReadFromUDP(b)
					if e != nil { 
						c.Close()
						sl.Lock(); delete(sessions, sa.String()); delete(lastActive, sa.String()); sl.Unlock()
						break 
					}
					ln.WriteToUDP(b[:m], sa)
					atomic.AddInt64(&cnt.Rx, int64(m))
					
					sl.Lock(); lastActive[sa.String()] = time.Now(); sl.Unlock()
				}
			}(newConn, srcAddr)
		}
	}
}

func copyCount(dst io.Writer, src io.Reader, c *int64) {
	b := make([]byte, 32*1024)
	for { n, e := src.Read(b); if n>0 { atomic.AddInt64(c, int64(n)); dst.Write(b[:n]) }; if e!=nil { break } }
}

// ================= HELPERS =================
func loadConfig() { f, err := os.Open(ConfigFile); if err == nil { defer f.Close(); json.NewDecoder(f).Decode(&config) } }
func saveConfig() { f, _ := os.Create(ConfigFile); defer f.Close(); json.NewEncoder(f).Encode(&config) }
func md5Hash(s string) string { h := md5.New(); h.Write([]byte(s)); return hex.EncodeToString(h.Sum(nil)) }
func setupSignalHandler() { c := make(chan os.Signal, 1); signal.Notify(c, os.Interrupt, syscall.SIGTERM); go func() { <-c; os.Exit(0) }() }
func formatBytes(b int64) string {
	const u = 1024; if b < u { return fmt.Sprintf("%d B", b) }
	div, exp := int64(u), 0; for n := b / u; n >= u; n /= u { div *= u; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ================= UI TEMPLATES =================

const setupHtml = `<!DOCTYPE html><html><head><title>GoRelay Setup</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:linear-gradient(135deg,#f5f7fa 0%,#c3cfe2 100%);display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,.1);width:100%;max-width:360px;animation:fadeIn .5s ease-out}h2{text-align:center;color:#333;margin-bottom:30px;font-weight:600}label{display:block;margin-bottom:8px;color:#666;font-size:14px;font-weight:500}input{width:100%;padding:12px;border:1px solid #e1e4e8;border-radius:6px;box-sizing:border-box;font-size:14px;transition:0.2s;margin-bottom:20px}input:focus{border-color:#007bff;outline:none;box-shadow:0 0 0 3px rgba(0,123,255,.1)}button{width:100%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;transition:0.2s}button:hover{background:#0056b3}button:active{transform:scale(.98)}@keyframes fadeIn{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}</style></head><body><form class="card" method="POST"><h2>初始化配置</h2><label>管理员账号</label><input name="username" required><label>管理员密码</label><input type="password" name="password" required><label>Agent 通信 Token</label><input name="token" required><button>启动服务</button></form></body></html>`

const loginHtml = `<!DOCTYPE html><html><head><title>GoRelay Login</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:linear-gradient(135deg,#e0eaec 0%,#4b6cb7 100%);display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,.2);width:100%;max-width:350px;animation:zoomIn .4s cubic-bezier(0.175, 0.885, 0.32, 1.275)}h2{text-align:center;color:#333;margin-bottom:30px;font-weight:700}input{width:100%;padding:13px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box;font-size:15px;margin-bottom:15px;transition:all .3s}input:focus{border-color:#4b6cb7;box-shadow:0 0 8px rgba(75,108,183,.2);outline:none}button{width:100%;padding:13px;background:linear-gradient(to right, #4b6cb7, #182848);color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:transform .1s}button:hover{opacity:.9}button:active{transform:scale(.97)}@keyframes zoomIn{from{opacity:0;transform:scale(.8)}to{opacity:1;transform:scale(1)}}</style></head><body><form class="card" method="POST"><h2>登录面板</h2><input name="username" placeholder="账号" required><input type="password" name="password" placeholder="密码" required><button>登 录</button></form></body></html>`

const dashboardHtml = `
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8"><title>GoRelay Pro</title>
<style>
:root{--w:220px;--c:#0d6efd;--bg:#f8f9fa}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;height:100vh;background:var(--bg)}
.sidebar{width:var(--w);background:#212529;color:#fff;display:flex;flex-direction:column}
.brand{padding:20px;font-size:18px;font-weight:700;text-align:center;border-bottom:1px solid #343a40;letter-spacing:1px}
.menu{flex:1;padding-top:10px}
.item{display:block;padding:12px 20px;color:#adb5bd;text-decoration:none;cursor:pointer;border-left:3px solid transparent;transition:.2s}
.item:hover,.item.active{background:#343a40;color:#fff;border-left-color:var(--c)}
.user{padding:20px;text-align:center;border-top:1px solid #343a40}
.logout{display:block;margin-top:10px;background:#dc3545;color:#fff;text-decoration:none;padding:5px;border-radius:3px;font-size:12px}
.main{flex:1;padding:30px;overflow-y:auto}
.page{display:none}.page.active{display:block}
.card{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.05);margin-bottom:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:20px}
.stat-card{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.05);display:flex;justify-content:space-between;align-items:center}
.stat-n{font-size:24px;font-weight:700;color:#333}.stat-l{color:#666;font-size:13px}
table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;border-bottom:1px solid #eee}
.badge{padding:3px 8px;border-radius:10px;font-size:12px;background:#d1e7dd;color:#0f5132}
input,select{padding:8px;border:1px solid #ddd;border-radius:4px;width:100%;box-sizing:border-box}
button{background:var(--c);color:#fff;border:none;padding:8px 15px;border-radius:4px;cursor:pointer}
.cmd-box{background:#2d2d2d;color:#f8f8f2;padding:15px;border-radius:4px;font-family:monospace;word-break:break-all;margin-top:10px}
.form-g{margin-bottom:10px}label{display:block;font-size:12px;margin-bottom:5px;color:#666}
.grid-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;align-items:end}
</style>
</head>
<body>
<div class="sidebar">
    <div class="brand">GoRelay Pro</div>
    <div class="menu">
        <a class="item active" onclick="nav('dashboard',this)">📊 仪表盘监控</a>
        <a class="item" onclick="nav('deploy',this)">🚀 部署节点</a>
        <a class="item" onclick="nav('rules',this)">🔗 转发管理</a>
        <a class="item" onclick="nav('settings',this)">⚙️ 系统设置</a>
    </div>
    <div class="user"><div>{{.User}}</div><a href="/logout" class="logout">安全退出</a></div>
</div>
<div class="main">
    <div id="dashboard" class="page active">
        <div class="stats">
            <div class="stat-card" style="border-left:4px solid #0d6efd"><div><div class="stat-n">{{formatBytes .TotalTraffic}}</div><div class="stat-l">累计消耗流量</div></div><div style="font-size:24px">📶</div></div>
            <div class="stat-card" style="border-left:4px solid #198754"><div><div class="stat-n">{{len .Agents}}</div><div class="stat-l">在线节点</div></div><div style="font-size:24px">📡</div></div>
            <div class="stat-card" style="border-left:4px solid #ffc107"><div><div class="stat-n">{{len .Rules}}</div><div class="stat-l">活跃规则</div></div><div style="font-size:24px">⚡</div></div>
        </div>
        <div class="card">
            <h3 style="margin-top:0">在线节点状态</h3>
            {{if .Agents}}
            <table><thead><tr><th>节点名称</th><th>IP地址</th><th>状态</th></tr></thead><tbody>
            {{range .Agents}}<tr><td><b>{{.Name}}</b></td><td>{{.RemoteIP}}</td><td><span class="badge">运行中</span></td></tr>{{end}}
            </tbody></table>
            {{else}}<p style="text-align:center;color:#999">暂无节点在线</p>{{end}}
        </div>
    </div>

    <div id="deploy" class="page">
        <div class="card">
            <h3 style="margin-top:0">生成部署命令</h3>
            <p style="color:#666;font-size:13px">在 B/C 机器上执行此命令，即可自动下载、授权、后台运行。</p>
            <div style="display:flex;gap:10px;margin-top:15px">
                <input id="agentName" placeholder="节点名称 (如: HK-Node)" value="Node-1" style="max-width:300px">
                <button onclick="genCmd()">生成后台命令</button>
            </div>
            <div class="cmd-box"><div id="cmdText">...</div></div>
            <div style="text-align:right;margin-top:10px"><button onclick="copyCmd()" style="background:#555">复制命令</button></div>
        </div>
    </div>

    <div id="rules" class="page">
        <div class="card">
            <h3 style="margin-top:0">添加转发规则</h3>
            <form action="/add" method="POST">
                <div class="grid-form">
                    <div class="form-g"><label>入口 (B)</label><select name="entry_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                    <div class="form-g"><label>入口端口</label><input type="number" name="entry_port" required></div>
                    <div style="text-align:center;padding-bottom:12px">➜</div>
                    <div class="form-g"><label>出口 (C)</label><select name="exit_agent">{{range .Agents}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></div>
                    <div class="form-g"><label>目标IP</label><input name="target_ip" placeholder="1.1.1.1 或 [::1]" required></div>
                    <div class="form-g"><label>目标端口</label><input type="number" name="target_port" required></div>
                    <div class="form-g"><label>协议</label><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select></div>
                    <div class="form-g"><button>添加</button></div>
                </div>
            </form>
        </div>
        <div class="card">
            <h3 style="margin-top:0">规则列表</h3>
            <table><thead><tr><th>链路 (B ➜ C)</th><th>最终目标</th><th>协议</th><th>流量 (Tx / Rx)</th><th>操作</th></tr></thead><tbody>
            {{range .Rules}}<tr>
                <td>{{.EntryAgent}}:{{.EntryPort}} ➜ {{.ExitAgent}}</td>
                <td>{{.TargetIP}}:{{.TargetPort}}</td>
                <td><span style="background:#eee;padding:2px 6px;border-radius:4px;font-size:12px">{{.Protocol}}</span></td>
                <td style="font-family:monospace;font-size:13px;color:#555">↑{{formatBytes .TotalTx}} &nbsp; ↓{{formatBytes .TotalRx}}</td>
                <td><a href="/delete?id={{.ID}}" style="color:#dc3545;text-decoration:none">删除</a></td>
            </tr>{{end}}
            </tbody></table>
        </div>
    </div>

    <div id="settings" class="page">
        <div class="card" style="max-width:400px">
            <h3 style="margin-top:0">系统设置</h3>
            <form action="/update_settings" method="POST">
                <div class="form-g"><label>修改密码</label><input type="password" name="password" placeholder="留空则不修改"></div>
                <div class="form-g"><label>Agent Token</label><input name="token" value="{{.Token}}"></div>
                <button style="margin-top:10px">保存设置</button>
            </form>
        </div>
    </div>
</div>
<script>
    var host=location.hostname, port="9999", token="{{.Token}}", dwUrl="{{.DownloadURL}}";
    
    // IPv6 兼容性处理
    if (host.indexOf(':') > -1 && host.indexOf('[') === -1) {
        host = '[' + host + ']';
    }

    function nav(id, el) {
        window.location.hash = id;
        document.querySelectorAll('.page').forEach(e=>e.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        if(el){ 
            document.querySelectorAll('.item').forEach(e=>e.classList.remove('active')); 
            el.classList.add('active'); 
        } else {
             document.querySelectorAll('.item').forEach(e=>e.classList.remove('active'));
             var targetBtn = document.querySelector('a[onclick*="'+id+'"]');
             if(targetBtn) targetBtn.classList.add('active');
        }
    }

    if(location.hash) {
        nav(location.hash.substring(1));
    }

    function genCmd() {
        var n = document.getElementById('agentName').value;
        document.getElementById('cmdText').innerText = 'wget -q -O relay '+dwUrl+' && chmod +x relay && nohup ./relay -mode agent -name "'+n+'" -connect "'+host+':'+port+'" -token "'+token+'" >/dev/null 2>&1 &';
    }

    function copyCmd() {
        var t = document.getElementById('cmdText').innerText;
        if(navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(()=>alert('已复制'));
        else { var ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);alert('已复制'); }
    }

    // 自动刷新逻辑：只刷新仪表盘，其他页面不刷新
    setInterval(()=>{ 
        if(document.querySelector('.page.active').id === 'dashboard') {
            if(document.activeElement.tagName !== "INPUT") {
                location.reload();
            }
        }
    }, 5000);
</script></body></html>
`
