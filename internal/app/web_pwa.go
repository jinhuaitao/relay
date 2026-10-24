// handlers_pwa.go — PWA 支撑接口：manifest.json、Service Worker、矢量图标
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"net/http"
)

func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(manifestJSON))
}

func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(serviceWorkerJS))
}

func handleIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000")

	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
		<rect width="512" height="512" fill="#6366f1"/>
		<text x="50%" y="50%" dominant-baseline="central" text-anchor="middle" fill="#ffffff" font-family="system-ui, sans-serif" font-size="130" font-weight="bold" letter-spacing="4">Relay</text>
	</svg>`
	w.Write([]byte(svg))
}
