// app.go — 应用入口逻辑：命令行参数解析与运行模式分发
//
// 由原单文件 main.go（AppVersion v3.3.6）拆分而来，函数体未做任何改动；
// 唯一差异是入口函数由 main 更名为 Main，供仓库根目录的 main.go 调用。

package app

import (
	"flag"
	"log"
)

// Main 是整个程序的入口，按 -mode 分发到主控（master）或节点（agent）模式。
func Main() {
	setRLimit()
	mode := flag.String("mode", "master", "运行模式")
	name := flag.String("name", "", "Agent名称")
	connect := flag.String("connect", "", "Master地址")
	token := flag.String("token", "", "通信Token")
	serviceOp := flag.String("service", "", "install | uninstall")
	tlsFlag := flag.Bool("tls", false, "使用 TLS 加密连接")
	flag.Parse()

	if *serviceOp != "" {
		handleService(*serviceOp, *mode, *name, *connect, *token, *tlsFlag)
		return
	}

	setupSignalHandler()

	if *mode == "master" {
		initDB()
		loadConfig()
		runMaster()
	} else if *mode == "agent" {
		if *name == "" || *connect == "" || *token == "" {
			log.Fatal("Agent模式参数不足")
		}
		useTLS = *tlsFlag
		runAgent(*name, *connect, *token)
	} else {
		log.Fatal("未知模式")
	}
}
