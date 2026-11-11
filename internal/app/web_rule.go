// handlers_rule.go — 转发规则的增删改查、启停、流量重置与批量操作
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func handleAddRule(w http.ResponseWriter, r *http.Request) {
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)
	lbStrategy := r.FormValue("lb_strategy")
	if lbStrategy == "" {
		lbStrategy = "random"
	}

	finalBridgePort := fmt.Sprintf("%d", 20000+time.Now().UnixNano()%30000)

	mu.Lock()
	rules = append(rules, LogicalRule{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
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
		BridgePort:   finalBridgePort,
		LBStrategy:   lbStrategy,
	})
	saveConfigNoLock()
	mu.Unlock()
	addLog(r, "新增规则", fmt.Sprintf("备注: %s, 入口 %s:%s → 出口 %s:%s", r.FormValue("note"), r.FormValue("entry_agent"), r.FormValue("entry_port"), r.FormValue("exit_agent"), r.FormValue("target_port")))
	go pushConfigToAll()
	http.Redirect(w, r, "/#rules", http.StatusSeeOther)
}

func handleEditRule(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	limitGB, _ := strconv.ParseFloat(r.FormValue("traffic_limit"), 64)
	speedMB, _ := strconv.ParseFloat(r.FormValue("speed_limit"), 64)
	lbStrategy := r.FormValue("lb_strategy")
	if lbStrategy == "" {
		lbStrategy = "random"
	}

	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Group = r.FormValue("group")
			rules[i].Note = r.FormValue("note")
			rules[i].EntryAgent = r.FormValue("entry_agent")
			rules[i].EntryPort = r.FormValue("entry_port")
			rules[i].ExitAgent = r.FormValue("exit_agent")
			rules[i].TargetIP = r.FormValue("target_ip")
			rules[i].TargetPort = r.FormValue("target_port")
			rules[i].Protocol = r.FormValue("protocol")
			newLimit := int64(limitGB * 1024 * 1024 * 1024)
			if rules[i].TrafficLimit != newLimit {
				rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
			}
			rules[i].TrafficLimit = newLimit
			rules[i].SpeedLimit = int64(speedMB * 1024 * 1024)
			rules[i].LBStrategy = lbStrategy
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
	var nowDisabled bool
	mu.Lock()
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Disabled = !rules[i].Disabled
			nowDisabled = rules[i].Disabled
			break
		}
	}
	saveConfigNoLock()
	mu.Unlock()
	status := "已启用"
	if nowDisabled {
		status = "已禁用"
	}
	addLog(r, "启停规则", fmt.Sprintf("规则 ID: %s, 当前状态: %s", id, status))
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
	if r.Method != "POST" {
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
	if action == "delete" {
		var nr []LogicalRule
		for _, x := range rules {
			if !idMap[x.ID] {
				nr = append(nr, x)
			}
		}
		rules = nr
	} else if action == "enable" || action == "disable" || action == "reset" {
		for i := range rules {
			if idMap[rules[i].ID] {
				if action == "enable" {
					rules[i].Disabled = false
				}
				if action == "disable" {
					rules[i].Disabled = true
				}
				if action == "reset" {
					rules[i].TotalTx, rules[i].TotalRx = 0, 0
					rules[i].Alert80, rules[i].Alert95, rules[i].Alert100 = false, false, false
				}
			}
		}
	}
	saveConfigNoLock()
	mu.Unlock()

	batchLabels := map[string]string{"delete": "批量删除", "enable": "批量启用", "disable": "批量禁用", "reset": "批量重置流量"}
	if label, ok := batchLabels[action]; ok {
		addLog(r, "批量规则", fmt.Sprintf("%s %d 条规则", label, len(idMap)))
	}
	go pushConfigToAll()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	if a, ok := agents[name]; ok {
		if a.IsOnline {
			a.sendMessage(Message{Type: "uninstall"})
		}
		delete(agents, name) // 点击卸载时才彻底删除
	}
	mu.Unlock()
	addLog(r, "卸载节点", fmt.Sprintf("节点: %s", name))
	http.Redirect(w, r, "/#dashboard", http.StatusSeeOther)
}
