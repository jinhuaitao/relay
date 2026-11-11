// master.go — Master 主控：监听启动、Agent 长连接、统计上报、WebSocket 广播
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
)

func runMaster() {
	// WebSocket 与 HTTP 共用同源判定，阻止跨站 WebSocket 劫持（CSWSH）。
	wsUpgrader.CheckOrigin = func(r *http.Request) bool { return isSameOrigin(r) }

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			if atomic.CompareAndSwapInt32(&configDirty, 1, 0) {
				saveConfig()
			}
			cleanOldLogs()
			flushDailyStats()
			pruneOfflineAgents()
			cleanExpiredSessions()
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
	http.HandleFunc("/update_all_agents", authMiddleware(handleUpdateAllAgents))
	http.HandleFunc("/check_update", authMiddleware(handleCheckUpdate))
	http.HandleFunc("/gen_agent_token", authMiddleware(handleGenAgentToken))

	http.HandleFunc("/oauth/github/login", handleGithubLogin)
	http.HandleFunc("/oauth/github/callback", handleGithubCallback)

	http.HandleFunc("/manifest.json", handleManifest)
	http.HandleFunc("/sw.js", handleServiceWorker)
	http.HandleFunc("/vendor/", handleVendor)
	http.HandleFunc("/icons/", handleIcons)
	http.HandleFunc("/icon.svg", handleIcon) // 旧入口，保留兼容
	http.HandleFunc("/favicon.ico", handleFavicon)
	http.HandleFunc("/apple-touch-icon.png", handleAppleTouchIcon)
	http.HandleFunc("/apple-touch-icon-precomposed.png", handleAppleTouchIcon)

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
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" || len(name) > 64 {
		_, _ = w.Write([]byte(""))
		return
	}

	mu.Lock()
	if config.AgentTokens == nil {
		config.AgentTokens = make(map[string]string)
	}
	if config.AgentAddTimes == nil {
		config.AgentAddTimes = make(map[string]int64)
	}
	tk, exists := config.AgentTokens[name]
	if !exists {
		tk = generateUUID()
		config.AgentTokens[name] = tk
		config.AgentAddTimes[name] = time.Now().Unix() // 记录永久添加时间
		saveConfigNoLock()
	}
	mu.Unlock()

	w.Write([]byte(tk))
}

// --- WebSocket 推送：每连接独立发送队列 ---
//
// 旧实现直接在全局 wsMu 锁内对所有客户端同步 WriteMessage。一旦某个客户端
// 处于网络黑洞（笔记本合盖、切后台、拔网线），底层 TCP 发送窗口被填满，
// WriteMessage 会无限期阻塞，进而把广播循环和 wsMu 一起挂住，
// 表现为"所有面板同时停止刷新"且无法自愈。
//
// 现在改为：广播侧只做非阻塞入队，写操作交给每连接独立的 writePump，
// 并配合写超时与 ping/pong 心跳回收死连接。
const (
	wsSendQueue  = 8                // 单连接最多积压的帧数
	wsWriteWait  = 10 * time.Second // 单次写入超时
	wsPongWait   = 90 * time.Second // 多久收不到 pong 判定连接已死
	wsPingPeriod = 30 * time.Second // 心跳间隔
	wsMaxPayload = 4096             // 面板不向服务端发消息，限制入站体积

	// Agent 侧：认证帧必须在 15 秒内到达，之后每个心跳帧间隔不得超过 90 秒。
	// Agent 每秒发一次 ping，90 秒的容忍度足以覆盖 GC 抖动与短暂丢包，
	// 同时把"机器断电/NAT 表项过期"的发现时间从内核默认的十几分钟压到 1.5 分钟。
	agentAuthTimeout = 15 * time.Second
	agentReadTimeout = 90 * time.Second
)

type wsClient struct {
	conn *websocket.Conn
	send chan []byte
	done chan struct{}
	once sync.Once
}

// close 幂等地关闭 done 以通知 writePump 退出。
// send 通道刻意不关闭——广播侧可能正持有引用，关闭会触发 panic。
func (c *wsClient) close() {
	c.once.Do(func() { close(c.done) })
}

// writePump 是单连接的唯一写入方，串行化写入并施加超时。
func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingPeriod)
	defer ticker.Stop()
	for {
		select {
		case msg := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				removeWSClient(c)
				return
			}
		case <-ticker.C:
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteWait)); err != nil {
				removeWSClient(c)
				return
			}
		case <-c.done:
			return
		}
	}
}

// removeWSClient 从注册表摘除并关闭连接，可被多个协程并发调用。
func removeWSClient(c *wsClient) {
	wsMu.Lock()
	_, exists := wsClients[c]
	if exists {
		delete(wsClients, c)
	}
	wsMu.Unlock()
	if !exists {
		return
	}
	c.close()
	c.conn.Close()
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	c := &wsClient{
		conn: conn,
		send: make(chan []byte, wsSendQueue),
		done: make(chan struct{}),
	}

	wsMu.Lock()
	wsClients[c] = true
	wsMu.Unlock()

	go c.writePump()

	// 读循环只用于感知客户端断开。必须设读超时并要求客户端回 pong，
	// 否则浏览器被系统挂起后 ReadMessage 会永远阻塞，连接变成僵尸。
	conn.SetReadLimit(wsMaxPayload)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
	removeWSClient(c)
}

// broadcastToClients 把一帧已序列化的数据分发给所有面板连接。
// 入队是非阻塞的：队列满说明该客户端消费不过来，直接丢弃本帧。
// 这里绝不能同步写网络——否则一个卡死的浏览器会冻结所有面板。
func broadcastToClients(msg []byte) {
	wsMu.Lock()
	for c := range wsClients {
		select {
		case c.send <- msg:
		default:
		}
	}
	wsMu.Unlock()
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
			t1 := config.AgentAddTimes[agentList[i].Name]
			t2 := config.AgentAddTimes[agentList[j].Name]
			if t1 == t2 {
				return agentList[i].Name < agentList[j].Name
			}
			return t1 < t2
		})
		for _, a := range agentList {
			agentData = append(agentData, AgentStatusData{Name: a.Name, SysStatus: a.SysStatus, IsOnline: a.IsOnline})
		}

		for _, r := range rules {
			currentTx += r.TotalTx
			currentRx += r.TotalRx
			ruleData = append(ruleData, RuleStatusData{
				ID:            r.ID,
				Name:          r.Note,
				Group:         r.Group,
				Total:         r.TotalTx + r.TotalRx,
				Tx:            r.TotalTx,
				Rx:            r.TotalRx,
				UserCount:     r.UserCount,
				Limit:         r.TrafficLimit,
				Status:        r.TargetStatus,
				Latency:       r.TargetLatency,
				BridgeLatency: r.BridgeLatency,
			})
		}
		mu.Unlock()

		var logData []OpLog
		if db != nil {
			lRows, err := db.Query("SELECT time, ip, COALESCE(category,'') AS category, action, msg FROM logs ORDER BY id DESC LIMIT 15")
			if err == nil {
				for lRows.Next() {
					var l OpLog
					if err := lRows.Scan(&l.Time, &l.IP, &l.Category, &l.Action, &l.Msg); err == nil {
						logData = append(logData, l)
					}
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

		// 1. 先在锁外构建并序列化一次，所有客户端复用同一份字节
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
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		// 2. 非阻塞分发给所有客户端，单帧序列化结果复用
		broadcastToClients(msgBytes)
	}
}

func handleAgentConn(conn net.Conn) {
	defer conn.Close()
	// 开启 TCP keepalive：节点断电或链路黑洞时，内核能主动探测并关闭连接，
	// 不必等到默认的十几分钟重传超时（TCPKeepAlive 常量此前定义了却从未使用）。
	enableKeepAlive(conn)

	// 未认证阶段按行读取并限制单帧长度，避免恶意连接用超长 JSON 打爆内存。
	// bufio.Reader 会保留已缓冲的后续数据，认证通过后主循环继续从它解码。
	_ = conn.SetReadDeadline(time.Now().Add(agentAuthTimeout))
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil || len(line) > 64*1024 {
		return
	}
	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil || msg.Type != "auth" {
		return
	}
	dec := json.NewDecoder(br)

	data, ok := msg.Payload.(map[string]interface{})
	if !ok {
		return
	}
	reqToken, _ := data["token"].(string)
	name, _ := data["name"].(string)
	// --- 新增：获取节点汇报的 IP 和 测试端口 ---
	reportedIPv4, _ := data["ipv4"].(string)
	reportedIPv6, _ := data["ipv6"].(string)
	testPortFloat, _ := data["test_port"].(float64)
	testPort := int(testPortFloat)
	reportedVersion, _ := data["version"].(string)
	if reportedVersion == "" {
		reportedVersion = "未知"
	}
	// --------------------------------------

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

	// --- 新增：智能入站连通性测试 (优先全功能 IPv4，备用全功能 IPv6) ---
	finalIP := remoteIP
	if testPort > 0 {
		ipv4Ok := false
		if reportedIPv4 != "" {
			// 主控尝试连接节点的 IPv4
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", reportedIPv4, testPort), 2*time.Second); err == nil {
				c.Close()
				ipv4Ok = true
				finalIP = reportedIPv4
			}
		}
		// 如果 IPv4 连不通 (说明是出栈/NAT)，再去试 IPv6
		if !ipv4Ok && reportedIPv6 != "" {
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("[%s]:%d", reportedIPv6, testPort), 2*time.Second); err == nil {
				c.Close()
				finalIP = reportedIPv6
			}
		}
	}
	remoteIP = finalIP
	// ----------------------------------------------------------

	mu.Lock()
	if old, exists := agents[name]; exists && old.Conn != nil {
		_ = old.Conn.Close()
	}
	// 初始化为获取中
	agents[name] = &AgentInfo{Name: name, RemoteIP: remoteIP, Conn: conn, ConnectedAt: time.Now(), IsOnline: true, Version: reportedVersion, Region: "🌍 --"}
	mu.Unlock()

	// --- 新增：异步获取 IP 地理位置，并转换为 Emoji 国旗 ---
	go func(ipStr, agentName string) {
		host := ipStr
		if h, _, err := net.SplitHostPort(ipStr); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		// 只查询合法 IP，避免把 Agent 上报的任意字符串拼进外部 URL。
		if net.ParseIP(host) == nil {
			return
		}
		client := http.Client{Timeout: 3 * time.Second}
		// 明文 HTTP 的地理接口已换成支持 TLS 的 ipwho.is
		if resp, err := client.Get("https://ipwho.is/" + host + "?fields=country_code"); err == nil {
			defer resp.Body.Close()
			var res struct {
				CountryCode string `json:"country_code"`
				Success     bool   `json:"success"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&res) == nil && res.Success && len(res.CountryCode) == 2 {
				cc := strings.ToUpper(res.CountryCode)
				if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
					return
				}
				// 巧妙利用 Unicode 偏移量将两位字母转为国旗 Emoji (例如 US 会变成 🇺🇸)
				flag := string([]rune{rune(cc[0]) + 127397, rune(cc[1]) + 127397}) + " " + cc
				mu.Lock()
				if a, ok := agents[agentName]; ok {
					a.Region = flag
				}
				mu.Unlock()
			}
		}
	}(remoteIP, name)
	log.Printf("Agent上线: %s", name)
	addSystemLog(remoteIP, "Agent 上线", fmt.Sprintf("节点 %s 已连接", name))
	sendTelegram(fmt.Sprintf("🟢 节点上线通知\n名称: %s", tgEscape(name)))
	pushConfigToAll()

	for {
		// 每次读取前刷新超时：Agent 每秒发一次 ping，超过 agentReadTimeout
		// 没收到任何帧即视为连接已死，走下面的下线流程（标记离线 + 告警），
		// 避免节点实际已断流、面板却长期显示"在线"。
		_ = conn.SetReadDeadline(time.Now().Add(agentReadTimeout))
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
		curr.IsOnline = false // <--- 修改这里：不删除，仅标记离线
		mu.Unlock()
		sendTelegram(fmt.Sprintf("🔴 节点下线通知\n名称: %s", tgEscape(name)))
		// === 新增：将节点下线事件写入系统日志 ===
		addSystemLog(remoteIP, "Agent 下线", fmt.Sprintf("节点 %s 已断开连接", name))
	} else {
		mu.Unlock()
	}
}

func handleStatsReport(payload interface{}) {
	d, _ := json.Marshal(payload)
	var reports []TrafficReport
	json.Unmarshal(d, &reports)

	var alertMsgs []string
	limitTriggered := false

	mu.Lock()
	// 构建 O(1) 快速索引映射，消除 O(N*M) 的双层嵌套遍历
	ruleIndex := make(map[string]int, len(rules))
	for i := range rules {
		ruleIndex[rules[i].ID] = i
	}

	for _, rep := range reports {
		if strings.HasSuffix(rep.TaskID, "_entry") {
			rid := strings.TrimSuffix(rep.TaskID, "_entry")

			// 使用哈希映射直接定位规则
			if i, exists := ruleIndex[rid]; exists {
				rules[i].TotalTx += rep.TxDelta
				rules[i].TotalRx += rep.RxDelta
				rules[i].UserCount = rep.UserCount
				atomic.StoreInt32(&configDirty, 1)

				atomic.AddInt64(&dailyTxBuf, rep.TxDelta)
				atomic.AddInt64(&dailyRxBuf, rep.RxDelta)

				// --- 智能预警机制开始 ---
				limit := rules[i].TrafficLimit
				total := rules[i].TotalTx + rules[i].TotalRx
				if limit > 0 {
					pct := float64(total) / float64(limit)
					note := tgEscape(rules[i].Note)
					if pct >= 1.0 && !rules[i].Alert100 {
						rules[i].Alert100 = true
						alertMsgs = append(alertMsgs, fmt.Sprintf("🚨 <b>流量耗尽熔断</b>\n\n规则：【%s】\n状态：已切断连接\n说明：流量达到 100%%，该端口已自动熔断！", note))
						limitTriggered = true
					} else if pct >= 0.95 && pct < 1.0 && !rules[i].Alert95 {
						rules[i].Alert95 = true
						alertMsgs = append(alertMsgs, fmt.Sprintf("⚠️ <b>流量极高预警</b>\n\n规则：【%s】\n状态：即将熔断\n说明：流量已使用超过 95%%！", note))
					} else if pct >= 0.80 && pct < 0.95 && !rules[i].Alert80 {
						rules[i].Alert80 = true
						alertMsgs = append(alertMsgs, fmt.Sprintf("🔔 <b>流量使用预警</b>\n\n规则：【%s】\n状态：运行中\n说明：流量已使用超过 80%%。", note))
					}
				}
				// --- 智能预警机制结束 ---
			}
		}
	}
	mu.Unlock()

	// 锁外发送预警消息，避免死锁
	for _, msg := range alertMsgs {
		sendTelegram(msg)
	}
	if limitTriggered {
		go pushConfigToAll()
	}
}

func handleHealthReport(payload interface{}) {
	d, _ := json.Marshal(payload)
	var reports []HealthReport
	_ = json.Unmarshal(d, &reports)
	mu.Lock()
	defer mu.Unlock()
	// 建索引，避免每条上报都线性扫一遍规则表
	ruleIndex := make(map[string]int, len(rules))
	for i := range rules {
		ruleIndex[rules[i].ID] = i
	}
	for _, rep := range reports {
		if strings.HasSuffix(rep.TaskID, "_exit") {
			rid := strings.TrimSuffix(rep.TaskID, "_exit")
			if i, ok := ruleIndex[rid]; ok {
				rules[i].TargetStatus = (rep.Latency >= 0)
				rules[i].TargetLatency = rep.Latency
			}
		} else if strings.HasSuffix(rep.TaskID, "_entry") {
			rid := strings.TrimSuffix(rep.TaskID, "_entry")
			if i, ok := ruleIndex[rid]; ok {
				rules[i].BridgeLatency = rep.Latency
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
		if exit, ok := agents[r.ExitAgent]; ok && exit.IsOnline {
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
		if v.IsOnline {
			activeAgents[k] = v
		}
	}
	mu.Unlock()
	for n, a := range activeAgents {
		t := tasksMap[n]
		if t == nil {
			t = []ForwardTask{}
		}
		go func(a *AgentInfo, tasks []ForwardTask) {
			a.sendMessage(Message{Type: "update", Payload: tasks})
		}(a, t)
	}
}
