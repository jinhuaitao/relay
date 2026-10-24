// main.go — 可执行文件入口
//
// 仅做一件事：把控制权交给 internal/app。所有实现都在 internal/app 内，
// 这样仓库根目录保持干净，同时 internal/ 保证实现包不会被外部模块导入。

package main

import "relay/internal/app"

func main() {
	app.Main()
}
