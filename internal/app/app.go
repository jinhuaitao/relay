// app.go — 应用入口逻辑：命令行参数解析与运行模式分发

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
	decryptFile := flag.String("decrypt-backup", "", "解密一份 .db.enc 云备份（口令来自 GORELAY_BACKUP_PASSPHRASE 或标准输入）")
	outFile := flag.String("out", "", "解密输出路径，默认与输入同名 .db")
	flag.Parse()

	if *decryptFile != "" {
		runDecryptBackup(*decryptFile, *outFile)
		return
	}

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
