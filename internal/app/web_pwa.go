// web_pwa.go — PWA 支撑接口：manifest.json、Service Worker、图标与本地前端依赖

package app

import (
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
)

const (
	iconRootDir    = "web/icons"
	iconCacheCTL   = "public, max-age=604800"
	vendorCacheCTL = "public, max-age=604800"
)

var iconsDir = func() fs.FS {
	sub, err := fs.Sub(iconsFS, iconRootDir)
	if err != nil {
		return iconsFS
	}
	return sub
}()

var iconMIME = map[string]string{
	".png": "image/png",
	".svg": "image/svg+xml",
	".ico": "image/x-icon",
}

func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(manifestJSON))
}

func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(serviceWorkerJS))
}

func serveIcon(w http.ResponseWriter, r *http.Request, name string) {
	name = path.Clean("/" + name)[1:]
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
	_, _ = w.Write(data)
}

func handleIcons(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, strings.TrimPrefix(r.URL.Path, "/icons/"))
}

func handleIcon(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, "icon.svg")
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, "favicon.ico")
}

func handleAppleTouchIcon(w http.ResponseWriter, r *http.Request) {
	serveIcon(w, r, "apple-touch-icon.png")
}

// handleVendor 只暴露白名单内的四个本地资源，杜绝路径穿越。
func handleVendor(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var contentType string
	switch r.URL.Path {
	case "/vendor/chart.umd.min.js":
		data, contentType = chartJS, "application/javascript; charset=utf-8"
	case "/vendor/remixicon.css":
		data, contentType = remixiconCSS, "text/css; charset=utf-8"
	case "/vendor/fonts/remixicon.woff2":
		contentType = "font/woff2"
		b, err := fs.ReadFile(vendorFonts, "web/vendor/fonts/remixicon.woff2")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data = b
	case "/vendor/fonts/remixicon.woff":
		contentType = "font/woff"
		b, err := fs.ReadFile(vendorFonts, "web/vendor/fonts/remixicon.woff")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data = b
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", vendorCacheCTL)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
