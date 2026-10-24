// agent.go — Agent 节点：主控连接、心跳、目标健康探测
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

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
	// --- 新增：精准探测公网 IPv4 / IPv6 ---
	var publicIPv4, publicIPv6 string
	client4 := http.Client{Timeout: 3 * time.Second}
	if resp, err := client4.Get("http://ipv4.icanhazip.com"); err == nil {
		if b, err := io.ReadAll(resp.Body); err == nil {
			publicIPv4 = strings.TrimSpace(string(b))
		}
		resp.Body.Close()
	}
	client6 := http.Client{Timeout: 3 * time.Second}
	if resp, err := client6.Get("http://ipv6.icanhazip.com"); err == nil {
		if b, err := io.ReadAll(resp.Body); err == nil {
			publicIPv6 = strings.TrimSpace(string(b))
		}
		resp.Body.Close()
	}
	// ------------------------------------

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

		// 串行化对主控连接的写操作，避免 ticker 与主循环并发写导致数据交错
		var masterMu sync.Mutex
		writeMsg := func(m Message) {
			masterMu.Lock()
			defer masterMu.Unlock()
			json.NewEncoder(conn).Encode(m)
		}

		// --- 新增：开启临时测试端口，供主控测试入站连通性 ---
		testLn, _ := net.Listen("tcp", ":0")
		var testPort int
		if testLn != nil {
			testPort = testLn.Addr().(*net.TCPAddr).Port
			go func(ln net.Listener) {
				defer ln.Close()
				// 10 秒后自动关闭测试端口，防止端口泄露
				ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
				if c, err := ln.Accept(); err == nil {
					c.Close()
				}
			}(testLn)
		}
		// -------------------------------------------------

		// 修改：将 IPv4、IPv6 和 测试端口 一并发送，Payload 类型改为 interface{}
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
		send(Message{Type: "health", Payload: results})
	}
}
