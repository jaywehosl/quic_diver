package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"quicdiver/internal/client/config"
	"quicdiver/internal/client/control"
	"quicdiver/internal/client/notify"
	"quicdiver/internal/client/service"
)

// Deps — то, чем API управляет. Интерфейсами, а не готовыми объектами: панель
// должна быть проверяема без поднятого туннеля и WinDivert.
type Deps struct {
	// Service — сессия (туннель + перехват): включить, выключить, состояние.
	Service Sessioner
	// Control — управляющая связь с узлом, живущая независимо от перехвата.
	Control Controller
	// Config — чтение и сохранение настроек.
	Config ConfigStore
	// Quit гасит клиента целиком (пункт «Выйти» в трее).
	Quit func()
	// Notices — уведомления: то, о чём пользователь обязан узнать сам.
	Notices Notices
}

// Sessioner — часть service.Service, нужная панели.
type Sessioner interface {
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	Status() service.Status
}

// Controller — часть control.Control, нужная панели.
type Controller interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
	Status() control.Status
	SetNode(entries []config.Entry, token string)
}

// Notices — центр уведомлений, нужный панели.
type Notices interface {
	List() []notify.Event
	Unread() int
	MarkRead(id int64)
	Clear()
}

// ConfigStore — чтение и запись настроек клиента.
type ConfigStore interface {
	Get() config.Config
	Save(cfg config.Config) error
}

// Handler собирает роутер панели.
func Handler(tok Token, d Deps, ui http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/api/status", get(d.status))
	mux.Handle("/api/connect", post(d.connect))
	mux.Handle("/api/disconnect", post(d.disconnect))
	mux.Handle("/api/quit", post(d.quit))
	mux.Handle("/api/config", rw(d.getConfig, d.putConfig))
	mux.Handle("/api/rules/test", post(d.testRule))
	mux.Handle("/api/exits", get(d.exits))
	mux.Handle("/api/notifications", rw(d.listNotices, d.readNotices))
	// Всё под /api/node/ уходит на узел как есть: admin-API уже собран, и
	// дублировать здесь каждый его эндпоинт значило бы обновлять два места.
	mux.Handle("/api/node/", http.HandlerFunc(d.proxy))

	if ui != nil {
		mux.Handle("/", ui)
	}
	return guard(tok, mux)
}

// --- состояние ---

// statusView — всё, что панель показывает на главном экране.
//
// Туннель и перехват разведены намеренно: сервис поднят и узел на связи — это
// одно состояние, а «трафик машины идёт через узел» — другое. Трей рисует
// иконку ровно по этой паре.
type statusView struct {
	// Session — состояние перехвата: stopped | connecting | connected.
	Session string `json:"session"`
	// Since — когда состояние установилось.
	Since time.Time `json:"since"`
	// Attempts — сколько раз сессия переподнималась (видно «дёргается»).
	Attempts int `json:"attempts"`
	// Error — последняя ошибка сессии.
	Error string `json:"error,omitempty"`
	// Control — управляющая связь с узлом (живёт отдельно от перехвата).
	Control control.Status `json:"control"`
	// Node — точка входа из настроек.
	Node string `json:"node,omitempty"`
	// Configured — задан ли узел и токен. На первом запуске нет, и панель
	// должна вести к настройке, а не показывать пустой экран с ошибкой.
	Configured bool `json:"configured"`
}

func (d Deps) status(w http.ResponseWriter, r *http.Request) {
	st := d.Service.Status()
	cfg := d.Config.Get()

	v := statusView{
		Session: sessionName(st.State), Since: st.Since,
		Attempts: st.Attempts, Error: st.LastError,
		Control:    d.Control.Status(),
		Configured: len(cfg.Node.Entries) > 0 && cfg.Node.Token != "",
	}
	if len(cfg.Node.Entries) > 0 {
		v.Node = cfg.Node.Entries[0].Authority()
	}
	writeJSON(w, v)
}

func sessionName(s service.State) string {
	switch s {
	case service.StateConnecting:
		return "connecting"
	case service.StateConnected:
		return "connected"
	default:
		return "stopped"
	}
}

func (d Deps) connect(w http.ResponseWriter, r *http.Request) {
	if err := d.Service.Connect(r.Context()); err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	d.status(w, r)
}

func (d Deps) disconnect(w http.ResponseWriter, r *http.Request) {
	// Ждём реального завершения: сессия возвращает системе DNS и прокси уже
	// после отмены, и ответить раньше — соврать, что всё выключено.
	if err := d.Service.Disconnect(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	d.status(w, r)
}

func (d Deps) quit(w http.ResponseWriter, r *http.Request) {
	if d.Quit == nil {
		fail(w, http.StatusNotImplemented, errNoQuit)
		return
	}
	writeJSON(w, map[string]string{"result": "выключаюсь"})
	// Гасим после ответа: иначе панель не узнает, что команда принята.
	go func() {
		time.Sleep(200 * time.Millisecond)
		d.Quit()
	}()
}

// --- настройки ---

func (d Deps) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.Config.Get())
}

func (d Deps) putConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	// Правила проверяем ДО сохранения: записанный битый набор оставил бы клиента
	// без роутинга до ручной правки файла.
	if _, err := compileRules(cfg); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := d.Config.Save(cfg); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	// Управляющая связь идёт к узлу из настроек — сообщаем ей о правке сразу,
	// иначе панель продолжила бы показывать данные прежнего узла.
	d.Control.SetNode(cfg.Node.Entries, cfg.Node.Token)
	writeJSON(w, d.Config.Get())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
