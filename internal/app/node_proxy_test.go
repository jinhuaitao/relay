package app

import (
	"sync"
	"sync/atomic"
	"testing"
)

func clearProxyCaches() {
	for _, m := range []*sync.Map{&targetHealthMap, &rrCounters, &connCounters} {
		m.Range(func(k, _ interface{}) bool {
			m.Delete(k)
			return true
		})
	}
}

func TestSelectTargetStrategies(t *testing.T) {
	clearProxyCaches()
	defer clearProxyCaches()
	targets := []string{"a.example:80", "b.example:80"}

	targetHealthMap.Store("a.example:80", int64(100))
	targetHealthMap.Store("b.example:80", int64(10))
	if got := selectTarget("t", targets, "fastest"); got != "b.example:80" {
		t.Errorf("fastest 应选延迟最低目标，得到 %q", got)
	}

	n1, n2 := int64(5), int64(1)
	connCounters.Store("a.example:80", &n1)
	connCounters.Store("b.example:80", &n2)
	if got := selectTarget("t", targets, "least_conn"); got != "b.example:80" {
		t.Errorf("least_conn 应选连接最少目标，得到 %q", got)
	}

	first := selectTarget("rr-task", targets, "rr")
	second := selectTarget("rr-task", targets, "rr")
	if first == second {
		t.Errorf("rr 连续两次应选中不同目标，均为 %q", first)
	}

	if got := selectTarget("t", targets, "random"); got != targets[0] && got != targets[1] {
		t.Errorf("random 返回了非目标地址 %q", got)
	}
	if got := selectTarget("t", []string{}, "random"); got != "" {
		t.Errorf("空目标应返回空串，得到 %q", got)
	}
	_ = atomic.LoadInt64(&n1)
}

func TestIpTrackerCountsUniqueHosts(t *testing.T) {
	var count int64
	tracker := &IpTracker{refs: make(map[string]int), count: &count}
	tracker.Add("1.1.1.1:1000")
	tracker.Add("1.1.1.1:1001")
	tracker.Add("2.2.2.2:1000")
	if got := atomic.LoadInt64(&count); got != 2 {
		t.Fatalf("独立 IP 数应为 2，得到 %d", got)
	}
	tracker.Remove("1.1.1.1:1000")
	if got := atomic.LoadInt64(&count); got != 2 {
		t.Fatalf("同 IP 仍有连接时不应递减，得到 %d", got)
	}
	tracker.Remove("1.1.1.1:1001")
	tracker.Remove("2.2.2.2:1000")
	if got := atomic.LoadInt64(&count); got != 0 {
		t.Fatalf("全部断开后应归零，得到 %d", got)
	}
}
