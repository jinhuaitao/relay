// update.go — 自更新与节点/主控升级相关的 HTTP 处理器
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

func performSelfUpdate() error {
	arch := runtime.GOARCH
	osName := runtime.GOOS
	suffix := ""
	if osName == "linux" {
		suffix = "-linux-" + arch
	} else if osName == "darwin" {
		suffix = "-darwin-" + arch
	} else if osName == "windows" {
		suffix = "-windows-" + arch + ".exe"
	} else {
		return fmt.Errorf("不支持的操作系统")
	}

	targetURL := DownloadURL + suffix
	log.Printf("正在下载更新: %s", targetURL)

	resp, err := http.Get(targetURL)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取运行路径: %v", err)
	}

	tmpPath := exePath + ".new"
	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}
	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	// 完整性校验：防止把错误页 / 截断文件当作合法二进制覆盖自身
	if fi, serr := os.Stat(tmpPath); serr == nil && fi.Size() < 100*1024 {
		os.Remove(tmpPath)
		return fmt.Errorf("下载文件过小 (%d 字节)，可能不是合法二进制", fi.Size())
	}
	if runtime.GOOS == "linux" {
		if f, ferr := os.Open(tmpPath); ferr == nil {
			head := make([]byte, 4)
			f.Read(head)
			f.Close()
			if !(head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
				os.Remove(tmpPath)
				return fmt.Errorf("下载文件非合法 ELF 二进制，校验失败")
			}
		}
	}

	os.Chmod(tmpPath, 0755)

	oldPath := exePath + ".old"
	os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Rename(oldPath, exePath)
		return fmt.Errorf("覆盖文件失败: %v", err)
	}
	return nil
}

func handleUpdateSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	if err := performSelfUpdate(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	addLog(r, "系统更新", "面板版本更新成功，即将重启")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	go func() { time.Sleep(1 * time.Second); doRestart() }()
}

func handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	mu.Lock()
	agent, ok := agents[name]
	mu.Unlock()
	if !ok {
		http.Error(w, "Agent not found", 404)
		return
	}
	agent.sendMessage(Message{Type: "upgrade"})
	w.Write([]byte("ok"))
}

func handleUpdateAllAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	mu.Lock()
	count := 0
	// 遍历所有节点，仅向在线节点发送更新指令
	for _, agent := range agents {
		if agent.IsOnline {
			agent.sendMessage(Message{Type: "upgrade"})
			count++
		}
	}
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   count,
	})
}

func handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(GithubLatestAPI)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"has_update": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"has_update": false})
		return
	}

	remoteVer := strings.TrimPrefix(data.TagName, "v")
	currentVer := strings.TrimPrefix(AppVersion, "v")

	hasUpdate := compareVersions(remoteVer, currentVer) > 0

	json.NewEncoder(w).Encode(map[string]interface{}{
		"has_update":     hasUpdate,
		"latest_version": data.TagName,
		"current":        AppVersion,
	})
}
