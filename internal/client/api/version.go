package api

import (
	"runtime/debug"
	"sync"
	"time"
)

// version — чем собран клиент.
//
// Видимая версия закрывает целый класс путаницы: «поправил, пересобрал, а
// поведение прежнее» почти всегда означает, что запущен другой файл или
// открыта вкладка со старой панелью. Спорить об этом вслепую — терять часы.
type version struct {
	// Revision — ревизия из git (её кладёт сам компилятор).
	Revision string `json:"revision,omitempty"`
	// Built — когда собрано.
	Built string `json:"built,omitempty"`
	// Dirty — сборка из дерева с несохранёнными правками.
	Dirty bool `json:"dirty,omitempty"`
	// Go — версия компилятора.
	Go string `json:"go,omitempty"`
}

var (
	versionOnce sync.Once
	versionInfo version
)

func buildVersion() version {
	versionOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		versionInfo.Go = info.GoVersion
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) > 12 {
					versionInfo.Revision = s.Value[:12]
				} else {
					versionInfo.Revision = s.Value
				}
			case "vcs.time":
				if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
					versionInfo.Built = t.Local().Format("2006-01-02 15:04")
				}
			case "vcs.modified":
				versionInfo.Dirty = s.Value == "true"
			}
		}
	})
	return versionInfo
}
