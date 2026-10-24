// types.go — 核心数据结构定义（规则、节点、消息、报表等）
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

type LogicalRule struct {
	ID            string `json:"id"`
	Group         string `json:"group"`
	Note          string `json:"note"`
	EntryAgent    string `json:"entry_agent"`
	EntryPort     string `json:"entry_port"`
	ExitAgent     string `json:"exit_agent"`
	TargetIP      string `json:"target_ip"`
	TargetPort    string `json:"target_port"`
	Protocol      string `json:"protocol"`
	BridgePort    string `json:"bridge_port"`
	TrafficLimit  int64  `json:"traffic_limit"`
	Disabled      bool   `json:"disabled"`
	SpeedLimit    int64  `json:"speed_limit"`
	LBStrategy    string `json:"lb_strategy"`
	TotalTx       int64  `json:"total_tx"`
	TotalRx       int64  `json:"total_rx"`
	UserCount     int64  `json:"user_count"`
	TargetStatus  bool   `json:"-"`
	TargetLatency int64  `json:"-"`
	Alert80       bool   `json:"alert_80"`
	Alert95       bool   `json:"alert_95"`
	Alert100      bool   `json:"alert_100"`

	BridgeLatency int64  `json:"-"`
	EntryIP       string `json:"-"`
}

type OpLog struct {
	Time     string `json:"time"`
	IP       string `json:"ip"`
	Category string `json:"category"`
	Action   string `json:"action"`
	Msg      string `json:"msg"`
}

type DailyStat struct {
	Date string `json:"Date"`
	Tx   int64  `json:"Tx"`
	Rx   int64  `json:"Rx"`
}

type AppConfig struct {
	WebUser            string            `json:"web_user"`
	WebPass            string            `json:"web_pass"`
	AgentToken         string            `json:"agent_token"`
	AgentTokens        map[string]string `json:"agent_tokens"`
	AgentAddTimes      map[string]int64  `json:"agent_add_times"`
	AgentPorts         string            `json:"agent_ports"`
	MasterDomain       string            `json:"master_domain"`
	PanelDomain        string            `json:"panel_domain"`
	IsSetup            bool              `json:"is_setup"`
	TgBotToken         string            `json:"tg_bot_token"`
	TgChatID           string            `json:"tg_chat_id"`
	TwoFAEnabled       bool              `json:"two_fa_enabled"`
	TwoFASecret        string            `json:"two_fa_secret"`
	GithubClientID     string            `json:"github_client_id"`
	GithubClientSecret string            `json:"github_client_secret"`
	GithubAllowedUsers string            `json:"github_allowed_users"`
	TrafficResetDay    int               `json:"traffic_reset_day"`
	LastResetMonth     string            `json:"last_reset_month"`
	R2AccessKey        string            `json:"r2_access_key"`
	R2SecretKey        string            `json:"r2_secret_key"`
	R2Endpoint         string            `json:"r2_endpoint"`
	R2Bucket           string            `json:"r2_bucket"`
	Rules              []LogicalRule     `json:"saved_rules"`
	Logs               []OpLog           `json:"logs"`
}

type ForwardTask struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	Target     string `json:"target"`
	SpeedLimit int64  `json:"speed_limit"`
	LBStrategy string `json:"lb_strategy"`
}

type TrafficReport struct {
	TaskID    string `json:"task_id"`
	TxDelta   int64  `json:"tx"`
	RxDelta   int64  `json:"rx"`
	UserCount int64  `json:"uc"`
}

type HealthReport struct {
	TaskID  string `json:"task_id"`
	Latency int64  `json:"lat"`
}

type AgentInfo struct {
	Name        string     `json:"name"`
	RemoteIP    string     `json:"remote_ip"`
	Conn        net.Conn   `json:"-"`
	SysStatus   string     `json:"sys_status"`
	ConnectedAt time.Time  `json:"-"`
	Version     string     `json:"version"`
	Region      string     `json:"region"`
	IsOnline    bool       `json:"is_online"`
	writeMu     sync.Mutex `json:"-"`
}

// sendMessage 串行化对该 Agent 连接的写操作，避免并发 JSON 写交错导致 Agent 侧解码失败
func (a *AgentInfo) sendMessage(msg Message) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.Conn == nil {
		return fmt.Errorf("agent %s 连接已关闭", a.Name)
	}
	return json.NewEncoder(a.Conn).Encode(msg)
}

type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type TrafficCounter struct {
	Rx int64
	Tx int64
}

type udpSession struct {
	conn       *net.UDPConn
	lastActive time.Time
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type WSDashboardData struct {
	TotalTraffic int64             `json:"total_traffic"`
	SpeedTx      int64             `json:"speed_tx"`
	SpeedRx      int64             `json:"speed_rx"`
	Agents       []AgentStatusData `json:"agents"`
	Rules        []RuleStatusData  `json:"rules"`
	Logs         []OpLog           `json:"logs"`
}

type AgentStatusData struct {
	Name      string `json:"name"`
	SysStatus string `json:"sys_status"`
	IsOnline  bool   `json:"is_online"`
}

type RuleStatusData struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Group         string `json:"group"`
	Total         int64  `json:"total"`
	Tx            int64  `json:"tx"`
	Rx            int64  `json:"rx"`
	UserCount     int64  `json:"uc"`
	Limit         int64  `json:"limit"`
	Status        bool   `json:"status"`
	Latency       int64  `json:"latency"`
	BridgeLatency int64  `json:"bridge_latency"`
}
