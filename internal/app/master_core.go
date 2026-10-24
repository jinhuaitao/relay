// master.go — Master 主控：监听启动、Agent 长连接、统计上报、WebSocket 广播
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

func runMaster() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			if atomic.CompareAndSwapInt32(&configDirty, 1, 0) {
				saveConfig()
			}
			cleanOldLogs()
			flushDailyStats()
			pruneOfflineAgents()
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
					lRows.Scan(&l.Time, &l.IP, &l.Category, &l.Action, &l.Msg)
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

		// 1. 先构建好需要发送的消息对象 (这就是编译器之前找不到的 msg)
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

		// 2. 在锁内，循环外部完成且仅完成一次 JSON 序列化
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			wsMu.Unlock()
			continue
		}

		// 3. 遍历客户端发送原生 Byte 数据，极大节省 CPU 和内存分配
		for client := range wsClients {
			if err := client.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
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
	if old, exists := agents[name]; exists {
		old.Conn.Close()
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
		client := http.Client{Timeout: 3 * time.Second}
		// 使用免费接口查询 IP 信息
		if resp, err := client.Get("http://ip-api.com/json/" + host + "?fields=countryCode"); err == nil {
			defer resp.Body.Close()
			var res struct {
				CountryCode string `json:"countryCode"`
			}
			if json.NewDecoder(resp.Body).Decode(&res) == nil && len(res.CountryCode) == 2 {
				cc := strings.ToUpper(res.CountryCode)
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
		} else if strings.HasSuffix(rep.TaskID, "_entry") { // --- 新增：截获入口到出口的延迟 ---
			rid := strings.TrimSuffix(rep.TaskID, "_entry")
			for i := range rules {
				if rules[i].ID == rid {
					rules[i].BridgeLatency = rep.Latency
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
