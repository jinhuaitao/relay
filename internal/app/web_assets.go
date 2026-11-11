// web_assets.go — 前端资源（编译期用 go:embed 内嵌进二进制）
//
// 前端脚本、图标字体、样式全部随二进制分发，运行时不依赖任何外部 CDN，
// 内网/离线部署也能完整渲染；同时消除了第三方脚本被篡改的供应链风险。

package app

import "embed"

//go:embed web/setup.html
var setupHtml string

//go:embed web/login.html
var loginHtml string

//go:embed web/dashboard.html
var dashboardHtml string

//go:embed web/manifest.json
var manifestJSON string

//go:embed web/sw.js
var serviceWorkerJS string

//go:embed web/icons
var iconsFS embed.FS

//go:embed web/vendor/chart.umd.min.js
var chartJS []byte

//go:embed web/vendor/remixicon.css
var remixiconCSS []byte

// 只打包现代浏览器实际会用到的两种字体格式，避免二进制无谓膨胀。
//
//go:embed web/vendor/fonts/remixicon.woff2 web/vendor/fonts/remixicon.woff
var vendorFonts embed.FS
