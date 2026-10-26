// web_pwa.go — PWA 支撑接口：manifest.json、Service Worker、图标资源
//
// 图标全部来自 internal/app/web/icons/（go:embed 内嵌），
// 一套资源同时服务 PWA 安装、iOS 添加到主屏、浏览器标签页与 Safari 固定标签。

package app

import (
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
)

const (
	iconRootDir = "web/icons" // 内嵌目录
	// 图标文件名固定、内容极少变动，给一周缓存；升级后最多一周内自动换新
	iconCacheCTL = "public, max-age=604800"
)

// 图标目录的只读文件系统视图（相对 web/icons）
var iconsDir = func() fs.FS {
	sub, err := fs.Sub(iconsFS, iconRootDir)
	if err != nil {
		return iconsFS
	}
	return sub
}()

// 扩展名 -> MIME（Go 内置表未必包含 .ico，这里显式声明）
var iconMIME = map[string]string{
	".png": "image/png",
	".svg": "image/svg+xml",
	".ico": "image/x-icon",
}

func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// manifest 变更后需尽快生效，但不希望每次导航都重新拉取
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(manifestJSON))
}

func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	// SW 必须每次校验，否则更新无法下发
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(serviceWorkerJS))
}

// serveIcon 从内嵌资源中输出单个图标文件。
func serveIcon(w http.ResponseWriter, r *http.Request, name string) {
	name = path.Clean("/" + name)[1:] // 去掉前导 /，并消解 .. 之类的路径穿越
	if name == "" || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}

	data, err := fs.ReadFile(iconsDir, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ct, ok := iconMIME[strings.ToLower(path.Ext(name))]
	if !ok {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", iconCacheCTL)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

// handleIcons 服务 /icons/* 下的全部图标（manifest 中的图标都走这里）。
func handleIcons(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, strings.TrimPrefix(r.URL.Path, "/icons/"))
}

// handleIcon 兼容旧入口 /icon.svg（历史 manifest 与外部书签可能仍在引用）。
func handleIcon(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, "icon.svg")
}

// handleFavicon 响应浏览器默认发起的 /favicon.ico 请求，避免 404 噪音。
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, "favicon.ico")
}

// handleAppleTouchIcon 响应 iOS 的兜底请求（页面已显式声明 apple-touch-icon）。
func handleAppleTouchIcon(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, "apple-touch-icon.png")
}
