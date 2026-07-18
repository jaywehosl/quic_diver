// Package config — файл настроек клиента.
//
// В релизе клиент запускается без аргументов командной строки: всё, что раньше
// задавалось флагами, живёт здесь, а правит это веб-панель. Флаги остаются
// инструментом разработки и перекрывают файл (см. cmd/qd-client).
//
// Лежит рядом с драйвером — в рабочей папке клиента (%APPDATA%\QUICDiver на
// Windows, ~/.config/QUICDiver на прочих). Внутри токен доступа, поэтому файл
// пишется с правами 0600 и только атомарно: оборванная запись не должна
// оставить клиента с обрезанным конфигом, из которого он не поднимется.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Version — версия схемы файла. Растёт при несовместимых изменениях; читатель
// старую версию узнаёт и мигрирует, а не падает на незнакомых полях.
const Version = 1

// Config — полный набор настроек клиента.
type Config struct {
	Version int `json:"version"`

	Node      Node      `json:"node"`
	Capture   Capture   `json:"capture"`
	Routing   Routing   `json:"routing"`
	Transport Transport `json:"transport"`
	Panel     Panel     `json:"panel"`

	// Autoconnect — поднимать туннель сразу при старте сервиса. false — сервис
	// живёт и отдаёт панель, а трафик заворачивается только по команде
	// пользователя (туннель и перехват разделены намеренно).
	Autoconnect bool `json:"autoconnect"`
}

// Node — к чему подключаться.
type Node struct {
	// Entries — точки входа по порядку перебора. Первая рабочая выигрывает.
	Entries []Entry `json:"entries"`
	// Token — токен доступа к сети (приезжает из бандла подписки).
	Token string `json:"token"`
}

// Entry — одна точка входа.
//
// Addr и SNI разделены сознательно: адрес может быть голым IP, а имя в SNI —
// настоящим доменом. Тогда TLS-сертификат валиден, пробинг видит обычный сайт,
// а DNS в подключении не участвует вовсе — это резервный путь, когда домен
// заблокирован или его ответ подменяют.
type Entry struct {
	// Addr — host:port или ip:port узла.
	Addr string `json:"addr"`
	// SNI — имя для TLS и :authority. Пусто → берётся host из Addr.
	SNI string `json:"sni,omitempty"`
}

// Authority отдаёт имя, которым клиент представляется узлу.
func (e Entry) Authority() string {
	if e.SNI != "" {
		return e.SNI
	}
	host, _, err := splitHostPort(e.Addr)
	if err != nil {
		return e.Addr
	}
	return host
}

// Capture — что перехватывать.
type Capture struct {
	// IPv4/IPv6 — семейства. Оба false → оба (поведение по умолчанию).
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
	// Ports — только эти dst-порты; пусто → все.
	Ports []uint16 `json:"ports,omitempty"`
	// Processes — имена процессов для per-app перехвата; пусто → все.
	// Источник PID появится вместе с наблюдением SOCKET-слоя.
	Processes []string `json:"processes,omitempty"`
	// Bypass — префиксы мимо перехвата (сверх локальных сетей, которые клиент
	// исключает всегда).
	Bypass []string `json:"bypass,omitempty"`
	// ManageProxy — отключать системный прокси на время работы и вернуть при
	// остановке. Без этого приложения уйдут в прокси мимо нас.
	ManageProxy bool `json:"manage_proxy"`
	// ManageDNS — поднимать локальный резолвер и переводить на него систему.
	// Иначе DNS уедет мимо туннеля и провайдер подменит ответы.
	ManageDNS bool `json:"manage_dns"`
	// NAT46 — синтез A-записей для IPv6-only хостов: auto|on|off.
	NAT46 string `json:"nat46"`
}

// Routing — правила выбора выхода.
type Routing struct {
	// Rules — правила в порядке приоритета, напр. "dom:youtube.com=chain".
	Rules []string `json:"rules,omitempty"`
	// Default — метка выхода, когда ни одно правило не совпало.
	Default string `json:"default,omitempty"`
}

// Transport — параметры канала до узла.
type Transport struct {
	// Hybrid — TCP через CONNECT-стрим, UDP датаграммами. Выключение оставляет
	// чистую модель B (всё датаграммами) и режет скорость в разы.
	Hybrid bool `json:"hybrid"`
	// RecvWorkers — потоков захвата. 1 сохраняет порядок пакетов; больше
	// ускоряет приём, но переупорядочивание бьёт по отдаче.
	RecvWorkers int `json:"recv_workers"`
	// MTU локального стека.
	MTU int `json:"mtu"`
	// BrutalMbps — слать с этой полосой, игнорируя потери (0 — обычный CC).
	// Ставить НИЖЕ реальной полосы отдачи.
	BrutalMbps int `json:"brutal_mbps"`
}

// Panel — локальная веб-панель.
type Panel struct {
	// Addr — адрес прослушивания. Только loopback: панель не должна быть
	// доступна из сети.
	Addr string `json:"addr"`
}

// Default — конфигурация «из коробки».
func Default() Config {
	return Config{
		Version: Version,
		Capture: Capture{
			ManageProxy: true,
			ManageDNS:   true,
			NAT46:       "auto",
		},
		Routing:   Routing{Default: "direct"},
		Transport: Transport{Hybrid: true, RecvWorkers: 1, MTU: 1420},
		// Порт редкий и постоянный: панель открывается закладкой, а не поиском
		// свободного порта при каждом запуске.
		Panel: Panel{Addr: "127.0.0.1:47821"},
	}
}

// Dir — рабочая папка клиента (там же лежит драйвер).
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: рабочая папка: %w", err)
	}
	return filepath.Join(base, "QUICDiver"), nil
}

// Path — путь файла настроек.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load читает настройки. Файла нет — возвращает значения по умолчанию: первый
// запуск не должен требовать ручной подготовки.
func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Default(), err
	}
	return LoadFrom(path)
}

// LoadFrom читает настройки из указанного файла.
func LoadFrom(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Default(), fmt.Errorf("config: чтение %s: %w", path, err)
	}
	// Поверх дефолтов: отсутствующие в файле поля сохраняют разумные значения,
	// а не превращаются в нули (иначе старый конфиг обнулил бы новые настройки).
	cfg := Default()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Default(), fmt.Errorf("config: разбор %s: %w", path, err)
	}
	cfg.migrate()
	return cfg, nil
}

// migrate приводит старые версии схемы к текущей.
func (c *Config) migrate() {
	if c.Version == 0 {
		c.Version = Version
	}
}

// Save атомарно записывает настройки в рабочую папку.
func (c Config) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	return c.SaveTo(path)
}

// SaveTo атомарно записывает настройки в указанный файл.
//
// Пишем во временный файл рядом и переименовываем: обрыв на середине оставит
// старый рабочий конфиг, а не обрезанный новый. Токен внутри — права 0600.
func (c Config) SaveTo(path string) error {
	c.Version = Version
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: сериализация: %w", err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: создание %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("config: временный файл: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // после удачного Rename файла уже нет — ошибка не важна

	if err := tmp.Chmod(0o600); err != nil && !isWindows() {
		tmp.Close()
		return fmt.Errorf("config: права на %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("config: запись: %w", err)
	}
	// Сброс на диск до переименования: иначе после внезапной перезагрузки на
	// месте конфига может оказаться пустой файл.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("config: сброс на диск: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: закрытие: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: замена %s: %w", path, err)
	}
	return nil
}
