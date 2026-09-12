package host

import (
	"os"

	"github.com/shirou/gopsutil/v4/cpu"
	gophost "github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// Snapshot — состояние машины, не процесса агента и не воркеров nginx.
// В контейнере это cgroup, на железе — хост.
type Snapshot struct {
	Hostname string `json:"-"`
	CPU      CPU    `json:"cpu"`
	Memory   Memory `json:"memory"`
	UptimeS  uint64 `json:"uptime_s"`
}

type CPU struct {
	Cores  int     `json:"cores"`
	Usage  float64 `json:"usage"`
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type Memory struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
}

func Collect() Snapshot {
	s := Snapshot{}
	s.Hostname, _ = os.Hostname()

	if info, err := gophost.Info(); err == nil {
		s.UptimeS = info.Uptime
		if s.Hostname == "" {
			s.Hostname = info.Hostname
		}
	}

	if n, err := cpu.Counts(true); err == nil {
		s.CPU.Cores = n
	}
	// 0 — с прошлого вызова; первый пульс может быть нулевым, второй уже нормальный.
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		s.CPU.Usage = pct[0] / 100
	}
	if avg, err := load.Avg(); err == nil {
		s.CPU.Load1 = avg.Load1
		s.CPU.Load5 = avg.Load5
		s.CPU.Load15 = avg.Load15
	}

	if v, err := mem.VirtualMemory(); err == nil {
		s.Memory.Total = v.Total
		s.Memory.Used = v.Used
		s.Memory.Available = v.Available
	}

	return s
}
