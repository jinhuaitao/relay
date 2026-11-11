// update.go — 自更新与节点/主控升级相关的 HTTP 处理器
//
// 加固点：二进制只从官方 GitHub Release 下载，并用同批发布的 checksums.txt
// 做 SHA256 强校验（失败即放弃替换）；所有下载带超时与体积上限；
// 升级指令强制 POST，且网络写一律在全局锁外进行。

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func releaseAssetSuffix() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return "-linux-" + runtime.GOARCH, nil
	case "darwin":
		return "-darwin-" + runtime.GOARCH, nil
	case "windows":
		return "-windows-" + runtime.GOARCH + ".exe", nil
	default:
		return "", fmt.Errorf("不支持的操作系统")
	}
}

// expectedChecksum 解析 sha256sum 输出，只接受精确匹配的文件名。
func expectedChecksum(list, asset string) (string, bool) {
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || len(fields[0]) != 64 {
			continue
		}
		name := filepath.Base(strings.TrimPrefix(fields[len(fields)-1], "*"))
		if name == asset {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func fetchWithLimit(client *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("响应超过 %d 字节上限", limit)
	}
	return data, nil
}

func performSelfUpdate() error {
	suffix, err := releaseAssetSuffix()
	if err != nil {
		return err
	}
	asset := "relay" + suffix
	client := &http.Client{Timeout: 5 * time.Minute}

	// 1. 先取官方同批发布清单；拿不到就拒绝更新（fail closed）
	sumData, err := fetchWithLimit(client, ChecksumsURL, 1<<20)
	if err != nil {
		return fmt.Errorf("无法获取官方校验清单: %w", err)
	}
	expected, ok := expectedChecksum(string(sumData), asset)
	if !ok {
		return fmt.Errorf("官方校验清单中没有 %s，出于安全考虑已放弃更新", asset)
	}

	// 2. 下载二进制并逐一校验
	targetURL := DownloadURL + suffix
	log.Printf("正在下载更新: %s", targetURL)
	data, err := fetchWithLimit(client, targetURL, MaxUpdateSize)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	if len(data) < 100*1024 {
		return fmt.Errorf("下载文件过小 (%d 字节)，可能不是合法二进制", len(data))
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), expected) {
		return fmt.Errorf("SHA256 校验失败，已放弃替换（期望 %s）", expected)
	}
	if runtime.GOOS == "linux" && !bytesHasELFMagic(data) {
		return fmt.Errorf("下载文件非合法 ELF 二进制，校验失败")
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取运行路径: %w", err)
	}
	tmpPath := exePath + ".new"
	if err := os.WriteFile(tmpPath, data, 0755); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}

	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("备份当前版本失败: %w", err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Rename(oldPath, exePath)
		_ = os.Remove(tmpPath)
		return fmt.Errorf("覆盖文件失败: %w", err)
	}
	return nil
}

func bytesHasELFMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

func handleUpdateSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := performSelfUpdate(); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	addLog(r, "系统更新", "面板版本更新成功，即将重启")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	go func() { time.Sleep(1 * time.Second); doRestart() }()
}

func handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	mu.Lock()
	agent, ok := agents[name]
	online := ok && agent.IsOnline
	mu.Unlock()
	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}
	if !online {
		http.Error(w, "Agent offline", http.StatusConflict)
		return
	}
	if err := agent.sendMessage(Message{Type: "upgrade"}); err != nil {
		http.Error(w, "下发升级指令失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	_, _ = w.Write([]byte("ok"))
}

func handleUpdateAllAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	targets := make([]*AgentInfo, 0, len(agents))
	for _, agent := range agents {
		if agent.IsOnline {
			targets = append(targets, agent)
		}
	}
	mu.Unlock()

	count := 0
	for _, agent := range targets {
		if agent.sendMessage(Message{Type: "upgrade"}) == nil {
			count++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "count": count})
}

func handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(GithubLatestAPI)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"has_update": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"has_update": false})
		return
	}

	remoteVer := strings.TrimPrefix(data.TagName, "v")
	currentVer := strings.TrimPrefix(AppVersion, "v")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"has_update":     compareVersions(remoteVer, currentVer) > 0,
		"latest_version": data.TagName,
		"current":        AppVersion,
	})
}
