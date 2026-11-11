// service.go — 进程级运维：文件句柄上限、systemd/OpenRC 服务安装卸载、重启、信号处理

package app

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func setRLimit() {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		var rLimit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
			want := uint64(1000000)
			if rLimit.Max > 0 && want > rLimit.Max {
				want = rLimit.Max
			}
			rLimit.Cur = want
			_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		}
	}
}

func handleService(op, mode, name, connect, token string, useTLS bool) {
	if os.Geteuid() != 0 {
		log.Fatal("需 root 权限")
	}
	if op != "install" && op != "uninstall" {
		log.Fatal("未知的 service 操作")
	}
	if mode != "master" && mode != "agent" {
		log.Fatal("未知的运行模式")
	}
	// 这些参数会被拼进 systemd/OpenRC 单元文件，必须先排除引号与元字符，
	// 否则一个含 " 的节点名就能改写 ExecStart。
	if op == "install" {
		for _, p := range []struct{ label, value string }{
			{"name", name}, {"connect", connect}, {"token", token},
		} {
			if p.value != "" && !safeServiceArg(p.value) {
				log.Fatalf("参数 %s 含非法字符（禁止引号、空白、$、反引号等）", p.label)
			}
		}
	}

	exe, _ := os.Executable()
	exe, _ = filepath.Abs(exe)
	tlsParam := ""
	if useTLS {
		tlsParam = " -tls"
	}

	svcName := "relay"
	if mode == "agent" {
		svcName = "gorelay"
	}

	args := fmt.Sprintf("-mode %s -name \"%s\" -connect \"%s\" -token \"%s\"%s", mode, name, connect, token, tlsParam)
	isSys := false
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		isSys = true
	}
	isAlpine := false
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		isAlpine = true
	}

	if op == "install" {
		if isSys {
			c := fmt.Sprintf("[Unit]\nDescription=GoRelay Service (%s)\nAfter=network.target\n[Service]\nType=simple\nExecStart=%s %s\nRestart=always\nUser=root\nLimitNOFILE=1000000\n[Install]\nWantedBy=multi-user.target", svcName, exe, args)
			if err := os.WriteFile(fmt.Sprintf("/etc/systemd/system/%s.service", svcName), []byte(c), 0644); err != nil {
				log.Fatalf("写入 systemd 单元失败: %v", err)
			}
			_ = exec.Command("systemctl", "enable", svcName).Run()
			_ = exec.Command("systemctl", "restart", svcName).Run()
			log.Printf("Systemd 服务 %s 已安装", svcName)
		} else if isAlpine {
			c := fmt.Sprintf("#!/sbin/openrc-run\nname=\"%s\"\ncommand=\"%s\"\ncommand_args=\"%s\"\ncommand_background=true\npidfile=\"/run/%s.pid\"\nrc_ulimit=\"-n 1000000\"\noutput_log=\"/var/log/relay.log\"\nerror_log=\"/var/log/relay.log\"\ndepend(){ need net; }", svcName, exe, args, svcName)
			if err := os.WriteFile(fmt.Sprintf("/etc/init.d/%s", svcName), []byte(c), 0755); err != nil {
				log.Fatalf("写入 OpenRC 脚本失败: %v", err)
			}
			_ = exec.Command("rc-update", "add", svcName, "default").Run()
			_ = exec.Command("rc-service", svcName, "restart").Run()
			log.Printf("OpenRC 服务 %s 已安装", svcName)
		} else {
			// 兜底分支：旧实现把整串参数当单个 argv 传入并附带 "&"，实际无法启动。
			cmdArgs := []string{"-mode", mode}
			if mode == "agent" {
				cmdArgs = append(cmdArgs, "-name", name, "-connect", connect, "-token", token)
			}
			if useTLS {
				cmdArgs = append(cmdArgs, "-tls")
			}
			cmd := exec.Command(exe, cmdArgs...)
			if f, err := os.OpenFile("/var/log/relay.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				cmd.Stdout, cmd.Stderr = f, f
				defer f.Close()
			}
			if err := cmd.Start(); err != nil {
				log.Fatalf("后台启动失败: %v", err)
			}
			log.Printf("已后台启动 (pid=%d)，日志: /var/log/relay.log", cmd.Process.Pid)
		}
	} else {
		if isSys {
			_ = exec.Command("systemctl", "disable", svcName).Run()
			_ = exec.Command("systemctl", "stop", svcName).Run()
			_ = os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", svcName))
			_ = exec.Command("systemctl", "daemon-reload").Run()
		}
		if isAlpine {
			_ = exec.Command("rc-update", "del", svcName, "default").Run()
			_ = exec.Command("rc-service", svcName, "stop").Run()
			_ = os.Remove(fmt.Sprintf("/etc/init.d/%s", svcName))
		}
		log.Printf("服务 %s 已卸载", svcName)
	}
}

func doSelfUninstall() {
	log.Println("执行自毁程序...")
	services := []string{"relay", "gorelay"}

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/systemd/system/%s.service", s)); err == nil {
				_ = exec.Command("systemctl", "disable", s).Run()
				_ = exec.Command("systemctl", "stop", s).Run()
				_ = os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", s))
			}
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/init.d/%s", s)); err == nil {
				_ = exec.Command("rc-update", "del", s, "default").Run()
				_ = exec.Command("rc-service", s, "stop").Run()
				_ = os.Remove(fmt.Sprintf("/etc/init.d/%s", s))
			}
		}
	}

	exe, err := os.Executable()
	if err == nil {
		realPath, err := filepath.EvalSymlinks(exe)
		if err != nil {
			realPath = exe
		}
		absPath, _ := filepath.Abs(realPath)
		_ = os.Remove(absPath)
	}
	os.Exit(0)
}

func doRestart() {
	log.Println("🔄 接收到重启指令...")
	services := []string{"relay", "gorelay"}

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/systemd/system/%s.service", s)); err == nil {
				_ = exec.Command("systemctl", "restart", s).Start()
				time.Sleep(1 * time.Second)
				os.Exit(0)
				return
			}
		}
	}

	if _, err := os.Stat("/etc/init.d"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/init.d/%s", s)); err == nil {
				_ = exec.Command("rc-service", s, "restart").Start()
				time.Sleep(1 * time.Second)
				os.Exit(0)
				return
			}
		}
	}

	argv0, err := os.Executable()
	if err != nil {
		argv0 = os.Args[0]
	}
	if runtime.GOOS == "windows" {
		cmd := exec.Command(argv0, os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if e := cmd.Start(); e == nil {
			time.Sleep(500 * time.Millisecond)
		}
		os.Exit(0)
	} else {
		_ = syscall.Exec(argv0, os.Args, os.Environ())
	}
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("📢 正在安全关闭服务...")
		mu.Lock()
		for _, a := range agents {
			if a.Conn != nil {
				_ = a.Conn.Close()
			}
		}
		saveConfigNoLock()
		mu.Unlock()
		if db != nil {
			_ = db.Close()
		}
		os.Exit(0)
	}()
}
