// proxy.go — 转发内核：监听、负载均衡选路、TCP/UDP 双向复制与限速

package app

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

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
	if count, exists := t.refs[host]; !exists || count <= 0 {
		return
	}
	t.refs[host]--
	if t.refs[host] <= 0 {
		delete(t.refs, host)
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
			_ = c.Close()
		}
	}
	runningListeners.Store(t.ID, closeAll)

	// 任务可能在重连恢复路径中被创建，对应计数器未必已初始化；
	// 旧实现在此处直接做类型断言，缺失时会 panic 并带崩整个 Agent。
	v, ok := agentUserCounts.Load(t.ID)
	if !ok {
		uz := int64(0)
		agentUserCounts.Store(t.ID, &uz)
		v = &uz
	}
	userCountPtr, ok := v.(*int64)
	if !ok {
		return
	}
	ipTracker := &IpTracker{refs: make(map[string]int), count: userCountPtr}

	if t.Protocol == "tcp" || t.Protocol == "both" {
		go func() {
			ln, err := net.Listen("tcp", t.Listen)
			if err != nil {
				return
			}
			l.Lock()
			closers = append(closers, func() { _ = ln.Close() })
			l.Unlock()
			for {
				c, e := ln.Accept()
				if e != nil {
					break
				}
				l.Lock()
				if closed {
					_ = c.Close()
					l.Unlock()
					continue
				}
				activeConns[c] = struct{}{}
				l.Unlock()
				ipTracker.Add(c.RemoteAddr().String())
				go func(conn net.Conn) {
					pipeTCP(conn, t.ID, t.SpeedLimit, t.LBStrategy)
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
			closers = append(closers, func() { _ = ln.Close() })
			l.Unlock()
			handleUDP(ln, t.ID, ipTracker, t.SpeedLimit, t.LBStrategy)
		}()
	}
}

func selectTarget(tid string, targets []string, strategy string) string {
	var valid []string
	var latencies []int64

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if v, ok := targetHealthMap.Load(t); ok {
			lat := v.(int64)
			if lat >= 0 {
				valid = append(valid, t)
				latencies = append(latencies, lat)
			}
		}
	}

	if len(valid) == 0 {
		valid = targets
		latencies = make([]int64, len(targets))
	}
	if len(valid) == 0 {
		return ""
	}
	nonEmpty := false
	for _, t := range valid {
		if strings.TrimSpace(t) != "" {
			nonEmpty = true
			break
		}
	}
	if !nonEmpty {
		return ""
	}
	if len(valid) == 1 {
		return valid[0]
	}

	switch strategy {
	case "rr":
		v, _ := rrCounters.LoadOrStore(tid, new(uint64))
		c := v.(*uint64)
		idx := atomic.AddUint64(c, 1) % uint64(len(valid))
		return valid[idx]

	case "least_conn":
		var best string
		var minConn int64 = -1
		for _, t := range valid {
			v, _ := connCounters.LoadOrStore(t, new(int64))
			c := atomic.LoadInt64(v.(*int64))
			if minConn == -1 || c < minConn {
				minConn = c
				best = t
			}
		}
		if best == "" {
			best = valid[0]
		}
		return best

	case "fastest":
		var best string
		var minLat int64 = -1
		for i, t := range valid {
			lat := latencies[i]
			if minLat == -1 || lat < minLat {
				minLat = lat
				best = t
			}
		}
		if best == "" {
			best = valid[0]
		}
		return best

	default:
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(valid))))
		return valid[n.Int64()]
	}
}

func pipeTCP(src net.Conn, tid string, limit int64, strategy string) {
	defer src.Close()

	var targetStr string
	if v, ok := activeTargets.Load(tid); ok {
		targetStr = v.(string)
	} else {
		return
	}

	allTargets := strings.Split(targetStr, ",")
	bestTarget := selectTarget(tid, allTargets, strategy)
	if bestTarget == "" {
		return
	}

	vConn, _ := connCounters.LoadOrStore(bestTarget, new(int64))
	atomic.AddInt64(vConn.(*int64), 1)
	defer atomic.AddInt64(vConn.(*int64), -1)

	dst, err := net.DialTimeout("tcp", bestTarget, 2*time.Second)
	if err != nil {
		return
	}
	defer dst.Close()

	v, ok := agentTraffic.Load(tid)
	if !ok {
		return
	}
	cnt := v.(*TrafficCounter)
	go copyCount(dst, src, &cnt.Tx, limit)
	copyCount(src, dst, &cnt.Rx, limit)
}

func handleUDP(ln *net.UDPConn, tid string, tracker *IpTracker, limit int64, strategy string) {
	udpSessions := &sync.Map{}
	v, ok := agentTraffic.Load(tid)
	if !ok {
		return
	}
	cnt := v.(*TrafficCounter)

	// UDP 也遵守 SpeedLimit：超速直接丢包（符合 UDP 语义），不阻塞读循环。
	var udpLimiter *rate.Limiter
	if limit > 0 {
		burst := UDPBufferSize
		if limit > int64(burst) {
			burst = int(limit)
		}
		udpLimiter = rate.NewLimiter(rate.Limit(limit), burst)
	}

	go func() {
		for {
			time.Sleep(30 * time.Second)
			now := time.Now()
			udpSessions.Range(func(key, value interface{}) bool {
				s := value.(*udpSession)
				if now.Sub(s.lastActive) > 45*time.Second {
					_ = s.conn.Close()
					udpSessions.Delete(key)
					tracker.Remove(key.(string))
				}
				return true
			})
		}
	}()

	for {
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, srcAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			break
		}
		if udpLimiter != nil && !udpLimiter.AllowN(time.Now(), n) {
			udpBufPool.Put(bufPtr)
			continue
		}
		atomic.AddInt64(&cnt.Tx, int64(n))
		sAddr := srcAddr.String()
		val, ok := udpSessions.Load(sAddr)
		if ok {
			s := val.(*udpSession)
			s.lastActive = time.Now()
			_, _ = s.conn.Write(buf[:n])
			udpBufPool.Put(bufPtr)
		} else {
			var currentTargetStr string
			if v, ok := activeTargets.Load(tid); ok {
				currentTargetStr = v.(string)
			} else {
				udpBufPool.Put(bufPtr)
				continue
			}
			targets := strings.Split(currentTargetStr, ",")
			bestTarget := selectTarget(tid, targets, strategy)
			if bestTarget == "" {
				udpBufPool.Put(bufPtr)
				continue
			}

			vConn, _ := connCounters.LoadOrStore(bestTarget, new(int64))
			atomic.AddInt64(vConn.(*int64), 1)

			dstAddr, _ := net.ResolveUDPAddr("udp", bestTarget)
			newConn, err := net.DialUDP("udp", nil, dstAddr)
			if err != nil {
				atomic.AddInt64(vConn.(*int64), -1)
				udpBufPool.Put(bufPtr)
				continue
			}
			s := &udpSession{conn: newConn, lastActive: time.Now()}
			udpSessions.Store(sAddr, s)
			tracker.Add(sAddr)
			_, _ = newConn.Write(buf[:n])
			udpBufPool.Put(bufPtr)
			go func(c *net.UDPConn, sa *net.UDPAddr, k string, bt string) {
				bPtr := udpBufPool.Get().(*[]byte)
				defer udpBufPool.Put(bPtr)
				b := *bPtr
				for {
					_ = c.SetReadDeadline(time.Now().Add(65 * time.Second))
					m, _, e := c.ReadFromUDP(b)
					if e != nil {
						_ = c.Close()
						udpSessions.Delete(k)
						tracker.Remove(k)
						atomic.AddInt64(vConn.(*int64), -1)
						break
					}
					if udpLimiter != nil && !udpLimiter.AllowN(time.Now(), m) {
						continue
					}
					_, _ = ln.WriteToUDP(b[:m], sa)
					atomic.AddInt64(&cnt.Rx, int64(m))
				}
			}(newConn, srcAddr, sAddr, bestTarget)
		}
	}
}

func copyCount(dst io.Writer, src io.Reader, c *int64, limit int64) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	var limiter *rate.Limiter
	if limit > 0 {
		limiter = rate.NewLimiter(rate.Limit(limit), CopyBufferSize)
	}

	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			if limiter != nil {
				// 带超时的等待：连接已被对端关闭时，不能让极低速率的令牌桶
				// 把这个 goroutine 永久挂住。
				waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = limiter.WaitN(waitCtx, nr)
				cancel()
			}

			toWrite := buf[0:nr]
			for len(toWrite) > 0 {
				nw, werr := dst.Write(toWrite)
				if nw > 0 {
					atomic.AddInt64(c, int64(nw))
					toWrite = toWrite[nw:]
				}
				if werr != nil {
					return
				}
			}
		}
		if err != nil {
			break
		}
	}
}
