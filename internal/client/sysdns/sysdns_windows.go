//go:build windows

// Package sysdns подменяет системный DNS на время работы клиента.
//
// Зачем: приложения спрашивают DNS у роутера (192.168.x.1), а он — в guard-bypass
// как локальный трафик, поэтому запрос уходит МИМО туннеля, прямо к провайдеру.
// Провайдер отдаёт адрес своей заглушки (проверено: instagram.com → 188.186.154.88
// = *.ertelecom.ru), и туннель добросовестно везёт нас на подставной хост — TLS
// при этом ругается на чужой сертификат. Резолв обязан идти через узел.
//
// Ставим именно 127.0.0.1 (наш listener), а не публичный резолвер: Chrome в режиме
// «Automatic» включает свой DoH, узнав в системном DNS известного провайдера
// (8.8.8.8 → Google DoH), и уходит резолвить мимо нас. Loopback ему неизвестен,
// поэтому он остаётся на системном резолвере.
//
// Правим ВСЕ интерфейсы и ОБА семейства: Windows опрашивает резолверы всех
// активных адаптеров, и один пропущенный IPv6-адрес от роутера = утечка запроса
// провайдеру. Смена сети даёт новому адаптеру свежий DHCP-DNS — поэтому Apply
// идемпотентен и его перевызывает supervisor.
package sysdns

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ключи интерфейсов: у IPv4 и IPv6 стеков они разные, NameServer в каждом свой.
const (
	v4Ifaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	v6Ifaces = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`
)

// Loopback — адреса нашего listener'а.
const (
	Loopback4 = "127.0.0.1"
	Loopback6 = "::1"
)

// saved — прежнее значение NameServer одного интерфейса одного семейства.
// Поля экспортируемые: состояние переживает нас в файле (см. stash).
type saved struct {
	Key   string `json:"key"` // корневой ключ семейства
	GUID  string `json:"guid"`
	Value string `json:"value"`
	Had   bool   `json:"had"`
}

// Saved — состояние DNS до нашего вмешательства.
type Saved struct{ entries []saved }

// Apply прописывает наш резолвер всем интерфейсам обоих семейств и возвращает
// состояние для восстановления. Идемпотентен: наши же значения не сохраняет как
// «прежние» (иначе повторный вызов затёр бы настоящий DNS пользователя и вернуть
// его на выходе было бы уже нечем).
func Apply() (*Saved, error) {
	live, err := liveAdapters()
	if err != nil {
		return nil, err
	}
	s := &Saved{}
	for key, ns := range map[string]string{v4Ifaces: Loopback4, v6Ifaces: Loopback6} {
		for _, guid := range live {
			e, err := set(key, guid, ns)
			if err != nil {
				continue // ключа семейства у адаптера может не быть, адаптер мог исчезнуть
			}
			if e != nil {
				s.entries = append(s.entries, *e)
			}
		}
	}
	if len(s.entries) == 0 {
		return s, fmt.Errorf("не нашёл ни одного интерфейса для подмены DNS")
	}
	// Сохранить на диск ДО flush: если нас убьют следующей же секундой, прежний
	// DNS должен быть уже записан, иначе восстанавливать будет нечем.
	if err := s.stash(); err != nil {
		log.Printf("sysdns: не сохранить состояние на диск: %v (при аварийном завершении DNS придётся править вручную)", err)
	}
	flush()
	return s, nil
}

// Restore возвращает прежний DNS.
func (s *Saved) Restore() error {
	if s == nil {
		return nil
	}
	err := s.restore()
	if path, perr := stashPath(); perr == nil {
		_ = os.Remove(path) // вернули штатно — подбирать больше нечего
	}
	return err
}

func (s *Saved) restore() error {
	var firstErr error
	for _, e := range s.entries {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, e.Key+`\`+e.GUID, registry.SET_VALUE)
		if err != nil {
			continue // интерфейса больше нет — восстанавливать нечего
		}
		if e.Had {
			err = k.SetStringValue("NameServer", e.Value)
		} else {
			// своего DNS не было (адрес приходил по DHCP) — убираем статический
			err = k.DeleteValue("NameServer")
		}
		k.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	flush()
	return firstErr
}

// RestoreStale подбирает DNS, оставшийся от прошлого запуска, который завершился
// аварийно (паника, kill, BSOD — defer не отработал).
//
// Без этого машина остаётся с NameServer=127.0.0.1 навсегда: клиент не запущен,
// listener мёртв, и резолва нет вообще — «интернет пропал» без объяснимой причины.
//
// Вызывать ПОСЛЕ того, как listener занял свой порт, но ДО Apply: если параллельно
// работает другой экземпляр, он уже держит порт, мы упадём раньше и не сорвём ему
// подмену.
func RestoreStale() (bool, error) {
	path, err := stashPath()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil // файла нет — прошлый запуск закрылся штатно
	}
	var entries []saved
	if err := json.Unmarshal(data, &entries); err != nil {
		_ = os.Remove(path)
		return false, fmt.Errorf("испорченный %s: %w", path, err)
	}
	if len(entries) == 0 {
		_ = os.Remove(path)
		return false, nil
	}
	s := &Saved{entries: entries}
	if err := s.restore(); err != nil {
		return true, err
	}
	_ = os.Remove(path)
	return true, nil
}

// stash пишет прежнее состояние рядом с рабочими файлами клиента.
func (s *Saved) stash() error {
	path, err := stashPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(s.entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func stashPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "QUICDiver", "dns-restore.json"), nil
}

// set ставит NameServer одному интерфейсу. Возвращает nil, если там уже стоит
// наше значение (тогда сохранять нечего).
func set(key, guid, ns string) (*saved, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key+`\`+guid,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	e := &saved{Key: key, GUID: guid}
	if old, _, err := k.GetStringValue("NameServer"); err == nil {
		if strings.TrimSpace(old) == ns {
			return nil, nil // уже наш — не трогаем и не «сохраняем»
		}
		e.Value, e.Had = old, true
	}
	if err := k.SetStringValue("NameServer", ns); err != nil {
		return nil, fmt.Errorf("записать NameServer (%s): %w", guid, err)
	}
	return e, nil
}

// liveAdapters возвращает GUID'ы поднятых сетевых адаптеров.
//
// Спрашиваем ОС, а не реестр: там остаются ключи давно исчезнувших адаптеров и
// виртуальных (Hyper-V, WSL, VirtualBox) — подменять им DNS незачем. Судить об
// «активности» по адресу в реестре нельзя: у IPv6-ключей адреса нет вообще (он
// приходит из RA и в реестр не пишется), и такой фильтр молча пропустил бы
// подмену v6 — то есть оставил бы ровно ту утечку, ради которой всё это.
func liveAdapters() ([]string, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER

	size := uint32(15 * 1024)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		if i == 2 {
			return nil, fmt.Errorf("GetAdaptersAddresses: буфер не сходится")
		}
	}

	var out []string
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		out = append(out, windows.BytePtrToString(a.AdapterName))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("нет поднятых сетевых адаптеров")
	}
	return out, nil
}

// flush сбрасывает кеш резолвера, иначе смена DNS подействует не сразу и старые
// (подменённые провайдером) ответы будут жить до истечения их TTL.
func flush() {
	dnsapi := windows.NewLazyDLL("dnsapi.dll")
	_, _, _ = dnsapi.NewProc("DnsFlushResolverCache").Call()
}

// openKey открывает ключ интерфейса на чтение (используется проверками).
func openKey(key, guid string) (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, key+`\`+guid, registry.QUERY_VALUE)
}
