// agent.go — Agent 节点：主控连接、心跳、目标健康探测

package app

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func runAgent(name, masterAddr, token string) {
	// 公网 IP 探测一律走 HTTPS，避免明文请求泄露节点出口信息且可被篡改。
	var publicIPv4, publicIPv6 string
	client := http.Client{Timeout: 3 * time.Second}
	if resp, err := client.Get("https://ipv4.icanhazip.com"); err == nil {
		if b, err := io.ReadAll(io.LimitReader(resp.Body, 256)); err == nil {
			publicIPv4 = strings.TrimSpace(string(b))
		}
		resp.Body.Close()
	}
	if resp, err := client.Get("https://ipv6.icanhazip.com"); err == nil {
		if b, err := io.ReadAll(io.LimitReader(resp.Body, 256)); err == nil {
			publicIPv6 = strings.TrimSpace(string(b))
		}
		resp.Body.Close()
	}
	if net.ParseIP(publicIPv4) == nil {
		publicIPv4 = ""
	}
	if net.ParseIP(publicIPv6) == nil {
		publicIPv6 = ""
	}

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
		enableKeepAlive(conn)

		var masterMu sync.Mutex
		writeMsg := func(m Message) {
			masterMu.Lock()
			defer masterMu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = json.NewEncoder(conn).Encode(m)
		}

		testLn, _ := net.Listen("tcp", ":0")
		var testPort int
		if testLn != nil {
			testPort = testLn.Addr().(*net.TCPAddr).Port
			go func(ln net.Listener) {
				defer ln.Close()
				_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
				if c, err := ln.Accept(); err == nil {
					_ = c.Close()
				}
			}(testLn)
		}

		writeMsg(Message{Type: "auth", Payload: map[string]interface{}{
			"name": name, "token": token, "ipv4": publicIPv4, "ipv6": publicIPv6, "test_port": testPort, "version": AppVersion,
		}})

		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(1 * time.Second)
			h := time.NewTicker(20 * time.Second)
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
						writeMsg(Message{Type: "stats", Payload: reps})
					}
					writeMsg(Message{Type: "ping", Payload: getSysStatus()})
				case <-h.C:
					checkTargetHealth(writeMsg)
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
				writeMsg(Message{Type: "uninstalling"})
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
				_ = json.Unmarshal(d, &tasks)
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

// validPingHost 只允许合法 IP 或常规域名，避免目标地址以 "-" 开头被 ping 当成参数。
func validPingHost(h string) bool {
	h = strings.TrimSpace(strings.Trim(h, "[]"))
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
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
	if !validPingHost(host) {
		return -1, false
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

func checkTargetHealth(send func(Message)) {
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

			switch checkMode {
			case "ping":
				lat, success = doPing(target)
			case "mixed":
				start := time.Now()
				c, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err == nil {
					_ = c.Close()
					lat = time.Since(start).Milliseconds()
					success = true
				} else {
					lat, success = doPing(target)
				}
			default:
				start := time.Now()
				c, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err == nil {
					_ = c.Close()
					lat = time.Since(start).Milliseconds()
					success = true
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
		send(Message{Type: "health", Payload: results})
	}
}
