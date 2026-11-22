// proxy.go — 转发内核：监听、负载均衡选路、TCP/UDP 双向复制与限速
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

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
	ctx, cancel := context.WithCancel(context.Background())
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
		cancel() // Stop TCP pumps even when both are waiting on a rate limiter.
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
					pipeTCP(ctx, conn, t.ID, t.SpeedLimit, t.LBStrategy)
					l.Lock()
					delete(activeConns, conn)
					l.Unlock()
					ipTracker.Remove(conn.RemoteAddr().String())
				}(c)
			}
		}()
	}
	if t.Protocol == "udp" || t.Protocol == "both" {
		// stop 信号随 closeAll 下发，确保会话清理协程随规则删除退出，不再泄漏
		udpStop := make(chan struct{})
		l.Lock()
		closers = append(closers, func() { close(udpStop) })
		l.Unlock()
		go func() {
			addr, _ := net.ResolveUDPAddr("udp", t.Listen)
			ln, err := net.ListenUDP("udp", addr)
			if err != nil {
				return
			}
			l.Lock()
			closers = append(closers, func() { ln.Close() })
			l.Unlock()
			handleUDP(ln, t.ID, ipTracker, t.SpeedLimit, t.LBStrategy, udpStop)
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

	// 目标全部为空（规则未配置 target），返回空串让调用方放弃
	if len(valid) == 0 {
		return ""
	}
	// 去除仅含空串的退化情况
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

// consumeQuota 在转发字节后扣减剩余流量额度，耗尽即关闭该任务的监听
// （节点侧硬熔断）。与主控的推送式熔断互为兜底，消除上报周期内的超额流量。
func consumeQuota(tid string, n int64) {
	v, ok := taskRemaining.Load(tid)
	if !ok {
		return
	}
	if atomic.AddInt64(v.(*int64), -n) <= 0 {
		if closeFunc, ok := runningListeners.Load(tid); ok {
			closeFunc.(func())()
		}
	}
}

func pipeTCP(ctx context.Context, src net.Conn, tid string, limit int64, strategy string) {
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

	dialer := net.Dialer{Timeout: 2 * time.Second}
	dst, err := dialer.DialContext(ctx, "tcp", bestTarget)
	if err != nil {
		return
	}
	defer dst.Close()

	v, ok := agentTraffic.Load(tid)
	if !ok {
		return
	}
	relayTCPPair(ctx, src, dst, v.(*TrafficCounter), limit, tid, tcpHalfCloseIdle)
}

const tcpHalfCloseIdle = 2 * time.Minute

// Propagate a clean EOF as a FIN without closing the still-writable socket.
// Only half-closed connections have a forwarding idle deadline.
func relayTCPPair(ctx context.Context, src, dst net.Conn, cnt *TrafficCounter, limit int64, tid string, halfCloseIdle time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	finished := make(chan bool, 2)
	progress := make(chan struct{}, 1)
	var draining atomic.Bool
	touch := func() {
		if draining.Load() {
			select {
			case progress <- struct{}{}:
			default:
			}
		}
	}
	pump := func(to, from net.Conn, count *int64) {
		clean := false
		if copyCount(ctx, to, from, count, limit, tid, touch) == nil {
			if writer, ok := to.(interface{ CloseWrite() error }); ok {
				clean = writer.CloseWrite() == nil
			}
		}
		finished <- clean
	}
	go pump(dst, src, &cnt.Tx)
	go pump(src, dst, &cnt.Rx)

	pending := 2
	var timer *time.Timer
	var idle <-chan time.Time
drain:
	for {
		select {
		case clean := <-finished:
			pending--
			if pending == 0 {
				return
			}
			if !clean {
				break drain
			}
			timer = time.NewTimer(halfCloseIdle)
			defer timer.Stop()
			idle = timer.C
			draining.Store(true)
		case <-progress:
			timer.Reset(halfCloseIdle)
		case <-idle:
			// Prefer a write already queued when the idle timer fired.
			select {
			case <-progress:
				timer.Reset(halfCloseIdle)
			default:
				break drain
			}
		case <-ctx.Done():
			break drain
		}
	}

	// Abort socket I/O and limiter waits before releasing connection counters.
	cancel()
	src.Close()
	dst.Close()
	for range pending {
		<-finished
	}
}

func handleUDP(ln *net.UDPConn, tid string, tracker *IpTracker, limit int64, strategy string, stop <-chan struct{}) {
	udpSessions := &sync.Map{}
	v, ok := agentTraffic.Load(tid)
	if !ok {
		return
	}
	cnt := v.(*TrafficCounter)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
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
		}
	}()

	// 每个数据包从池中借还缓冲，避免长期独占导致池失效
	for {
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, srcAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			break
		}
		atomic.AddInt64(&cnt.Tx, int64(n))
		consumeQuota(tid, int64(n))
		sAddr := srcAddr.String()
		val, ok := udpSessions.Load(sAddr)
		if ok {
			s := val.(*udpSession)
			s.lastActive = time.Now()
			s.conn.Write(buf[:n])
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
			newConn.Write(buf[:n])
			udpBufPool.Put(bufPtr)
			go func(c *net.UDPConn, sa *net.UDPAddr, k string, bt string) {
				bPtr := udpBufPool.Get().(*[]byte)
				defer udpBufPool.Put(bPtr)
				b := *bPtr
				for {
					c.SetReadDeadline(time.Now().Add(65 * time.Second))
					m, _, e := c.ReadFromUDP(b)
					if e != nil {
						c.Close()
						udpSessions.Delete(k)
						tracker.Remove(k)
						atomic.AddInt64(vConn.(*int64), -1)
						break
					}
					ln.WriteToUDP(b[:m], sa)
					atomic.AddInt64(&cnt.Rx, int64(m))
					consumeQuota(tid, int64(m))
				}
			}(newConn, srcAddr, sAddr, bestTarget)
		}
	}
}

// copyCount returns nil only on a clean read EOF.
func copyCount(ctx context.Context, dst io.Writer, src io.Reader, c *int64, limit int64, tid string, progress func()) error {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	// 初始化官方令牌桶限速器
	var limiter *rate.Limiter
	if limit > 0 {
		// Limit(limit) 表示每秒允许的字节数，Burst 设为 32KB 应对缓冲区突发
		limiter = rate.NewLimiter(rate.Limit(limit), CopyBufferSize)
	}

	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			// 如果开启了限速，平滑消费令牌，替代粗暴的 time.Sleep
			if limiter != nil {
				if waitErr := limiter.WaitN(ctx, nr); waitErr != nil {
					return waitErr
				}
			}

			// 必须写完整个切片：dst.Write 允许短写，未补齐会截断转发流
			toWrite := buf[0:nr]
			for len(toWrite) > 0 {
				nw, werr := dst.Write(toWrite)
				if nw > 0 {
					atomic.AddInt64(c, int64(nw))
					consumeQuota(tid, int64(nw))
					toWrite = toWrite[nw:]
					progress()
				}
				if werr != nil {
					return werr
				}
				if nw == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
