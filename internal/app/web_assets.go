// web_assets.go — 前端资源（编译期用 go:embed 内嵌进二进制）
//
// 模板与静态文件位于 internal/app/web/，修改后重新编译即可生效；
// 对外仍是单文件二进制部署，运行时不依赖任何外部文件。

package app

import _ "embed"

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
