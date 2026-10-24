// service.go — 进程级运维：文件句柄上限、systemd/OpenRC 服务安装卸载、重启、信号处理
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

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
			rLimit.Cur = 1000000
			rLimit.Max = 1000000
			syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		}
	}
}

func handleService(op, mode, name, connect, token string, useTLS bool) {
	if os.Geteuid() != 0 {
		log.Fatal("需 root 权限")
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
			os.WriteFile(fmt.Sprintf("/etc/systemd/system/%s.service", svcName), []byte(c), 0644)
			exec.Command("systemctl", "enable", svcName).Run()
			exec.Command("systemctl", "restart", svcName).Run()
			log.Printf("Systemd 服务 %s 已安装", svcName)
		} else if isAlpine {
			c := fmt.Sprintf("#!/sbin/openrc-run\nname=\"%s\"\ncommand=\"%s\"\ncommand_args=\"%s\"\ncommand_background=true\npidfile=\"/run/%s.pid\"\nrc_ulimit=\"-n 1000000\"\ndepend(){ need net; }", svcName, exe, args, svcName)
			os.WriteFile(fmt.Sprintf("/etc/init.d/%s", svcName), []byte(c), 0755)
			exec.Command("rc-update", "add", svcName, "default").Run()
			exec.Command("rc-service", svcName, "restart").Run()
			log.Printf("OpenRC 服务 %s 已安装", svcName)
		} else {
			exec.Command("nohup", exe, args, "&").Start()
			log.Println("已通过 nohup 启动")
		}
	} else {
		if isSys {
			exec.Command("systemctl", "disable", svcName).Run()
			exec.Command("systemctl", "stop", svcName).Run()
			os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", svcName))
			exec.Command("systemctl", "daemon-reload").Run()
		}
		if isAlpine {
			exec.Command("rc-update", "del", svcName, "default").Run()
			exec.Command("rc-service", svcName, "stop").Run()
			os.Remove(fmt.Sprintf("/etc/init.d/%s", svcName))
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
				exec.Command("systemctl", "disable", s).Run()
				exec.Command("systemctl", "stop", s).Run()
				os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", s))
			}
		}
		exec.Command("systemctl", "daemon-reload").Run()
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/init.d/%s", s)); err == nil {
				exec.Command("rc-update", "del", s, "default").Run()
				exec.Command("rc-service", s, "stop").Run()
				os.Remove(fmt.Sprintf("/etc/init.d/%s", s))
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
		os.Remove(absPath)
	}
	os.Exit(0)
}

func doRestart() {
	log.Println("🔄 接收到重启指令...")

	services := []string{"relay", "gorelay"}

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/systemd/system/%s.service", s)); err == nil {
				exec.Command("systemctl", "restart", s).Start()
				time.Sleep(1 * time.Second)
				os.Exit(0)
				return
			}
		}
	}

	if _, err := os.Stat("/etc/init.d"); err == nil {
		for _, s := range services {
			if _, err := os.Stat(fmt.Sprintf("/etc/init.d/%s", s)); err == nil {
				exec.Command("rc-service", s, "restart").Start()
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
		// Windows 不支持 syscall.Exec，重新拉起自身后退出
		cmd := exec.Command(argv0, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e := cmd.Start(); e == nil {
			time.Sleep(500 * time.Millisecond)
		}
		os.Exit(0)
	} else {
		os.Stdin = nil
		os.Stdout = nil
		os.Stderr = nil
		syscall.Exec(argv0, os.Args, os.Environ())
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
			a.Conn.Close()
		}
		saveConfigNoLock()
		mu.Unlock()
		if db != nil {
			db.Close()
		}
		os.Exit(0)
	}()
}
