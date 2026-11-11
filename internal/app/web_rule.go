// handlers_rule.go — 转发规则的增删改查、启停、流量重置与批量操作
//
// 所有入口（新增/编辑/导入）统一走 validateRuleFields，避免非法端口、
// 未知协议或空目标被下发成 Agent 监听任务。

package app

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const clearSentinel = "__CLEAR__"

func validPort(s string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil && n >= 1 && n <= 65535
}

func validProtocol(s string) bool {
	return s == "tcp" || s == "udp" || s == "both"
}

func validLBStrategy(s string) bool {
	switch s {
	case "", "random", "rr", "least_conn", "fastest":
		return true
	}
	return false
}

func validTargetList(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" || len(p) > 253 {
			return false
		}
		for _, r := range p {
			if r < 32 || r == 127 || r == ' ' || r == '"' || r == '\'' {
				return false
			}
		}
	}
	return true
}

func randomBridgePort() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", 20000+time.Now().UnixNano()%30000)
	}
	return fmt.Sprintf("%d", 20000+int(binary.BigEndian.Uint32(b[:])%30000))
}

// validRuleID 限制 ID 字符集：ID 会被拼进 DOM id、CSS 选择器与 onclick 参数，
// 导入的第三方规则文件不能借此注入标记。
func validRuleID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func validateRuleFields(r *LogicalRule) error {
	if !validRuleID(r.ID) {
		return fmt.Errorf("规则 ID 只能包含字母、数字、- _ . 且不超过 128 字符")
	}
	if !validProtocol(r.Protocol) {
		return fmt.Errorf("协议必须是 tcp / udp / both")
	}
	if !validPort(r.EntryPort) || !validPort(r.TargetPort) || !validPort(r.BridgePort) {
		return fmt.Errorf("端口必须是 1–65535 的整数")
	}
	if strings.TrimSpace(r.EntryAgent) == "" || strings.TrimSpace(r.ExitAgent) == "" {
		return fmt.Errorf("入口与出口节点不能为空")
	}
	if !validTargetList(r.TargetIP) {
		return fmt.Errorf("目标地址不合法")
	}
	if !validLBStrategy(r.LBStrategy) {
		return fmt.Errorf("负载均衡策略不合法")
	}
	if r.TrafficLimit < 0 || r.SpeedLimit < 0 {
		return fmt.Errorf("流量/速率限制不能为负")
	}
	return nil
}

// validateImportedRules 校验并规整导入的规则列表，返回可直接落库的副本。
func validateImportedRules(list []LogicalRule) ([]LogicalRule, error) {
	if len(list) > 1000 {
		return nil, fmt.Errorf("单次最多导入 1000 条规则")
	}
	out := make([]LogicalRule, len(list))
	seen := make(map[string]bool, len(list))
	for i := range list {
		r := list[i]
		r.ID = strings.TrimSpace(r.ID)
		if r.ID == "" {
			r.ID = generateUUID()
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("存在重复规则 ID: %s", r.ID)
		}
		seen[r.ID] = true
		if r.BridgePort == "" {
			r.BridgePort = randomBridgePort()
		}
		if r.LBStrategy == "" {
			r.LBStrategy = "random"
		}
		if err := validateRuleFields(&r); err != nil {
			return nil, fmt.Errorf("第 %d 条规则: %w", i+1, err)
		}
		out[i] = r
	}
	return out, nil
}

func ruleFromForm(r *http.Request, id, bridge string) (LogicalRule, error) {
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)
	lb := r.FormValue("lb_strategy")
	if lb == "" {
		lb = "random"
	}
	rule := LogicalRule{
		ID:           id,
		Group:        r.FormValue("group"),
		Note:         r.FormValue("note"),
		EntryAgent:   r.FormValue("entry_agent"),
		EntryPort:    r.FormValue("entry_port"),
		ExitAgent:    r.FormValue("exit_agent"),
		TargetIP:     r.FormValue("target_ip"),
		TargetPort:   r.FormValue("target_port"),
		Protocol:     r.FormValue("protocol"),
		TrafficLimit: int64(limitGB * 1024 * 1024 * 1024),
		SpeedLimit:   int64(speedMB * 1024 * 1024),
		BridgePort:   bridge,
		LBStrategy:   lb,
	}
	if err := validateRuleFields(&rule); err != nil {
		return LogicalRule{}, err
	}
	return rule, nil
}

func handleAddRule(w http.ResponseWriter, r *http.Request) {
	rule, err := ruleFromForm(r, generateUUID(), randomBridgePort())
	if err != nil {
		http.Error(w, "规则参数不合法: "+err.Error(), http.StatusBadRequest)
		return
	}

	mu.Lock()
	rules = append(rules, rule)
	saveConfigNoLock()
	mu.Unlock()
	addLog(r, "新增规则", fmt.Sprintf("备注: %s, 入口 %s:%s → 出口 %s:%s", rule.Note, rule.EntryAgent, rule.EntryPort, rule.ExitAgent, rule.TargetPort))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleEditRule(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")

	mu.Lock()
	bridge := ""
	for i := range rules {
		if rules[i].ID == id {
			bridge = rules[i].BridgePort
			break
		}
	}
	mu.Unlock()
	if bridge == "" {
		http.Error(w, "规则不存在", http.StatusNotFound)
		return
	}

	updated, err := ruleFromForm(r, id, bridge)
	if err != nil {
		http.Error(w, "规则参数不合法: "+err.Error(), http.StatusBadRequest)
		return
	}

	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			updated.TotalTx = rules[i].TotalTx
			updated.TotalRx = rules[i].TotalRx
			updated.UserCount = rules[i].UserCount
			if rules[i].TrafficLimit != updated.TrafficLimit {
				updated.Alert80, updated.Alert95, updated.Alert100 = false, false, false
			} else {
				updated.Alert80, updated.Alert95, updated.Alert100 = rules[i].Alert80, rules[i].Alert95, rules[i].Alert100
			}
			rules[i] = updated
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	addLog(r, "编辑规则", fmt.Sprintf("规则 ID: %s", id))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleToggleRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Disabled = !rules[i].Disabled
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	addLog(r, "启停规则", fmt.Sprintf("规则 ID: %s", id))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleResetTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].TotalTx, rules[i].TotalRx = 0, 0
			rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	addLog(r, "重置流量", fmt.Sprintf("规则 ID: %s", id))
	go pushConfigToAll()
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
	saveConfigNoLock()
	mu.Unlock()
	addLog(r, "删除规则", fmt.Sprintf("规则 ID: %s", id))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleBatchRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	action := r.FormValue("action")
	ids := strings.Split(r.FormValue("ids"), ",")

	idMap := make(map[string]bool)
	for _, id := range ids {
		if id != "" {
			idMap[id] = true
		}
	}

	mu.Lock()
	switch action {
	case "delete":
		var nr []LogicalRule
		for _, x := range rules {
			if !idMap[x.ID] {
				nr = append(nr, x)
			}
		}
		rules = nr
	case "enable", "disable", "reset":
		for i := range rules {
			if !idMap[rules[i].ID] {
				continue
			}
			switch action {
			case "enable":
				rules[i].Disabled = false
			case "disable":
				rules[i].Disabled = true
			case "reset":
				rules[i].TotalTx, rules[i].TotalRx = 0, 0
				rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
			}
		}
	default:
		mu.Unlock()
		http.Error(w, "未知的批量操作", http.StatusBadRequest)
		return
	}
	saveConfigNoLock()
	mu.Unlock()

	batchLabels := map[string]string{"delete": "批量删除", "enable": "批量启用", "disable": "批量禁用", "reset": "批量重置流量"}
	if label, ok := batchLabels[action]; ok {
		addLog(r, "批量规则", fmt.Sprintf("%s %d 条规则", label, len(idMap)))
	}
	go pushConfigToAll()
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	var target *AgentInfo
	if a, ok := agents[name]; ok {
		target = a
		delete(agents, name)
	}
	mu.Unlock()
	// 网络写必须放在全局锁外，慢节点不能拖死面板
	if target != nil && target.IsOnline {
		_ = target.sendMessage(Message{Type: "uninstall"})
	}
	addLog(r, "卸载节点", fmt.Sprintf("节点: %s", name))
	http.Redirect(w, r, "/#dashboard", http.StatusSeeOther)
}
