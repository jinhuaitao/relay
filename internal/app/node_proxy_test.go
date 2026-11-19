package app

import (
	"fmt"
	"sync/atomic"
	"testing"
)

func clearHealth(targets ...string) {
	for _, tg := range targets {
		targetHealthMap.Delete(tg)
		connCounters.Delete(tg)
	}
}

func TestSelectTargetSingleAndEmpty(t *testing.T) {
	defer clearHealth("a:1")
	targetHealthMap.Store("a:1", int64(5))
	if got := selectTarget("t", []string{"a:1"}, "random"); got != "a:1" {
		t.Errorf("single target: got %q", got)
	}
	if got := selectTarget("t", []string{""}, "random"); got != "" {
		t.Errorf("empty target must return empty, got %q", got)
	}
	if got := selectTarget("t", nil, "rr"); got != "" {
		t.Errorf("nil targets must return empty, got %q", got)
	}
}

func TestSelectTargetSkipsUnhealthy(t *testing.T) {
	defer clearHealth("bad:1", "good:1")
	targetHealthMap.Store("bad:1", int64(-1))
	targetHealthMap.Store("good:1", int64(10))
	for i := 0; i < 20; i++ {
		if got := selectTarget("t", []string{"bad:1", "good:1"}, "random"); got != "good:1" {
			t.Fatalf("unhealthy target selected: %q", got)
		}
	}
}

func TestSelectTargetAllUnhealthyFallsBack(t *testing.T) {
	defer clearHealth("x:1", "y:1")
	targetHealthMap.Store("x:1", int64(-1))
	targetHealthMap.Store("y:1", int64(-1))
	got := selectTarget("t", []string{"x:1", "y:1"}, "random")
	if got != "x:1" && got != "y:1" {
		t.Errorf("fallback must pick one of the targets, got %q", got)
	}
}

func TestSelectTargetRoundRobin(t *testing.T) {
	defer clearHealth("a:1", "b:1")
	rrCounters.Delete("rr-test")
	targetHealthMap.Store("a:1", int64(1))
	targetHealthMap.Store("b:1", int64(1))
	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		seen[selectTarget("rr-test", []string{"a:1", "b:1"}, "rr")]++
	}
	if seen["a:1"] != 5 || seen["b:1"] != 5 {
		t.Errorf("rr should alternate evenly, got %v", seen)
	}
	rrCounters.Delete("rr-test")
}

func TestSelectTargetLeastConn(t *testing.T) {
	defer clearHealth("busy:1", "idle:1")
	targetHealthMap.Store("busy:1", int64(1))
	targetHealthMap.Store("idle:1", int64(1))
	v, _ := connCounters.LoadOrStore("busy:1", new(int64))
	atomic.StoreInt64(v.(*int64), 50)
	v, _ = connCounters.LoadOrStore("idle:1", new(int64))
	atomic.StoreInt64(v.(*int64), 1)
	if got := selectTarget("t", []string{"busy:1", "idle:1"}, "least_conn"); got != "idle:1" {
		t.Errorf("least_conn picked %q", got)
	}
}

func TestSelectTargetFastest(t *testing.T) {
	defer clearHealth("slow:1", "fast:1")
	targetHealthMap.Store("slow:1", int64(200))
	targetHealthMap.Store("fast:1", int64(3))
	if got := selectTarget("t", []string{"slow:1", "fast:1"}, "fastest"); got != "fast:1" {
		t.Errorf("fastest picked %q", got)
	}
}

func TestIpTracker(t *testing.T) {
	var count int64
	tr := &IpTracker{refs: make(map[string]int), count: &count}
	tr.Add("1.1.1.1:1000")
	tr.Add("1.1.1.1:2000") // 同 IP 不同端口只算一个用户
	tr.Add("2.2.2.2:1000")
	if atomic.LoadInt64(&count) != 2 {
		t.Fatalf("unique users: got %d", count)
	}
	tr.Remove("1.1.1.1:1000")
	if atomic.LoadInt64(&count) != 2 {
		t.Error("removing one of two refs must not decrement")
	}
	tr.Remove("1.1.1.1:2000")
	tr.Remove("2.2.2.2:1000")
	tr.Remove("2.2.2.2:1000") // 重复 Remove 不应变负
	if atomic.LoadInt64(&count) != 0 {
		t.Errorf("count should be 0, got %d", count)
	}
}

func TestConsumeQuotaFiresClose(t *testing.T) {
	tid := "quota-test"
	rem := int64(100)
	taskRemaining.Store(tid, &rem)
	closed := false
	runningListeners.Store(tid, func() { closed = true })
	defer func() {
		taskRemaining.Delete(tid)
		runningListeners.Delete(tid)
	}()

	consumeQuota(tid, 60)
	if closed {
		t.Fatal("must not close before quota exhausted")
	}
	consumeQuota(tid, 40)
	if !closed {
		t.Fatal("listener must be closed exactly when quota exhausted")
	}
	if atomic.LoadInt64(&rem) != 0 {
		t.Errorf("remaining should be 0, got %d", rem)
	}
}

func TestConsumeQuotaUnlimited(t *testing.T) {
	// 未登记额度的任务不受影响
	consumeQuota("no-such-task", 1<<40)
}

func TestAssignBridgePortAvoidsUsed(t *testing.T) {
	used := make(map[string]bool)
	for p := 20000; p < 49999; p++ {
		used[fmt.Sprintf("%d", p)] = true
	}
	// 只剩 49999 一个空位，线性兜底必须找到它
	got := assignBridgePort(used)
	if got != "49999" {
		t.Errorf("expected 49999, got %q", got)
	}
	used["49999"] = true
	if got := assignBridgePort(used); got != "" {
		t.Errorf("exhausted range must return empty, got %q", got)
	}
}

func TestPickBridgePortNoLockUnique(t *testing.T) {
	oldRules := rules
	rules = []LogicalRule{
		{ID: "r1", BridgePort: "20000", EntryPort: "8080"},
		{ID: "r2", BridgePort: "20001", EntryPort: "8081"},
	}
	defer func() { rules = oldRules }()

	for i := 0; i < 50; i++ {
		p := pickBridgePortNoLock()
		if p == "20000" || p == "20001" || p == "8080" || p == "8081" {
			t.Fatalf("picked colliding port %q", p)
		}
	}
}

func TestUDPBufferCoversMaxDatagram(t *testing.T) {
	if UDPBufferSize < 65535 {
		t.Fatalf("UDP buffer %d truncates max-size datagrams", UDPBufferSize)
	}
	b := udpBufPool.Get().(*[]byte)
	if len(*b) != UDPBufferSize {
		t.Errorf("pool buffer size mismatch")
	}
	udpBufPool.Put(b)
}