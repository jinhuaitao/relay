// sysinfo.go — 系统资源采集（CPU / 内存 / 磁盘占用）
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func getSysStatus() string {
	var cpuPct, memPct, diskPct float64

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/stat"); err == nil {
			lines := strings.Split(string(data), "\n")
			if len(lines) > 0 {
				fields := strings.Fields(lines[0])
				if len(fields) > 4 && fields[0] == "cpu" {
					var ticks [8]uint64
					for i := 1; i < len(fields) && i <= 8; i++ {
						ticks[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
					}
					idleTicks := ticks[3] + ticks[4]
					var totalTicks uint64
					for _, t := range ticks {
						totalTicks += t
					}

					cpuMu.Lock()
					if lastCPUTotal > 0 && totalTicks >= lastCPUTotal && idleTicks >= lastCPUIdle {
						diffIdle := float64(idleTicks - lastCPUIdle)
						diffTotal := float64(totalTicks - lastCPUTotal)
						if diffTotal > 0 {
							cpuPct = ((diffTotal - diffIdle) / diffTotal) * 100.0
						}
					}
					lastCPUIdle = idleTicks
					lastCPUTotal = totalTicks
					cpuMu.Unlock()
				}
			}
		}

		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			var total, available, free, buffers, cached uint64
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					val, _ := strconv.ParseUint(fields[1], 10, 64)
					if fields[0] == "MemTotal:" {
						total = val
					}
					if fields[0] == "MemAvailable:" {
						available = val
					}
					if fields[0] == "MemFree:" {
						free = val
					}
					if fields[0] == "Buffers:" {
						buffers = val
					}
					if fields[0] == "Cached:" {
						cached = val
					}
				}
			}
			if total > 0 {
				if available == 0 {
					available = free + buffers + cached
				}
				if available < total {
					memPct = (float64(total-available) / float64(total)) * 100.0
				}
			}
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs("/", &stat); err == nil {
			used := stat.Blocks - stat.Bfree
			nonRootTotal := used + stat.Bavail
			if nonRootTotal > 0 {
				diskPct = (float64(used) / float64(nonRootTotal)) * 100.0
			}
		}
	} else {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memPct = 1.0
		cpuPct = float64(runtime.NumGoroutine())
	}

	if cpuPct < 0 {
		cpuPct = 0
	} else if cpuPct > 100 {
		cpuPct = 100
	}
	if memPct < 0 {
		memPct = 0
	} else if memPct > 100 {
		memPct = 100
	}
	if diskPct < 0 {
		diskPct = 0
	} else if diskPct > 100 {
		diskPct = 100
	}

	return fmt.Sprintf("CPU:%.1f|MEM:%.1f|DSK:%.1f", cpuPct, memPct, diskPct)
}
