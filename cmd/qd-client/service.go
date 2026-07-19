package main

import (
	"context"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"quicdiver/internal/client/api"
	"quicdiver/internal/client/config"
	"quicdiver/internal/client/control"
	"quicdiver/internal/client/notify"
	"quicdiver/internal/client/panel"
	"quicdiver/internal/client/service"
	"quicdiver/internal/client/tray"
)

// liveConfig — настройки в памяти с записью на диск.
//
// Панель правит их на ходу, поэтому чтение и запись идут через одну точку:
// иначе сохранение из панели и чтение при переподключении разошлись бы во
// времени, и клиент поднялся бы на старом узле.
type liveConfig struct {
	mu  sync.Mutex
	cfg config.Config
}

func (c *liveConfig) Get() config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func (c *liveConfig) Save(cfg config.Config) error {
	if err := cfg.Save(); err != nil {
		return err
	}
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
	return nil
}

// clientRuntime — то, что живёт весь запуск клиента.
type clientRuntime struct {
	svc     *service.Service
	ctl     *control.Control
	cfg     *liveConfig
	notices *notify.Center
	token   api.Token
	addr    string
	quit    context.CancelFunc
}

// startRuntime поднимает панель и управляющую связь.
//
// Порядок важен: панель обязана подняться даже когда узел недоступен — иначе
// пользователю негде поправить адрес узла, из-за которого всё и не работает.
func startRuntime(ctx context.Context, o options, cfg config.Config, quit context.CancelFunc) (*clientRuntime, error) {
	tok, err := api.NewToken()
	if err != nil {
		return nil, err
	}
	live := &liveConfig{cfg: withRuntimeNode(cfg, o)}
	cfg = live.Get()
	notices := notify.New()

	// InsecureSkipVerify тянется из dev-режима: у стендов самоподписанные
	// сертификаты. Для боевой сборки это флаг, а не поведение по умолчанию.
	ctl := control.New(control.DialNode(true))
	ctl.SetNode(cfg.Node.Entries, cfg.Node.Token)

	rt := &clientRuntime{
		svc: service.New(func(sctx context.Context) error { return run(sctx, o) },
			service.DefaultBackoff()),
		ctl: ctl, cfg: live, notices: notices, token: tok,
		addr: panelAddr(cfg), quit: quit,
	}

	h := api.Handler(tok, api.Deps{
		Service: rt.svc, Control: ctl, Config: live, Notices: notices,
		Quit: func() { quit() },
		// Контекст жизни клиента, а не запроса: сессия обязана пережить
		// ответ панели.
		Base: ctx,
	}, panel.Handler())

	ln, err := net.Listen("tcp", rt.addr)
	if err != nil {
		return nil, err
	}
	rt.addr = ln.Addr().String()
	srv := panel.Server(rt.addr, h)
	go func() {
		if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
			log.Printf("панель остановилась: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
		ctl.Close()
	}()

	log.Printf("панель: %s", rt.panelURL())
	return rt, nil
}

// withRuntimeNode дописывает в настройки узел, с которым клиент реально
// работает.
//
// Узел приходит тремя путями: файлом настроек, флагом и вшитым при сборке
// значением. Панель и управляющая связь читают только файл, поэтому без этой
// сшивки релизная сборка при первом запуске показывала бы «узел не настроен» —
// хотя узел вшит в неё и она к нему подключается. Наступали на это вживую.
//
// Файл главнее: если пользователь уже настроил узел через панель, флаг его не
// перебивает — иначе правка в панели молча откатывалась бы при перезапуске.
func withRuntimeNode(cfg config.Config, o options) config.Config {
	if len(cfg.Node.Entries) == 0 && o.server != "" {
		cfg.Node.Entries = []config.Entry{{Addr: o.server, SNI: o.authority}}
	}
	if cfg.Node.Token == "" {
		cfg.Node.Token = o.token
	}
	return cfg
}

// panelAddr — где слушать панель. Только петля: панель управляет клиентом
// целиком, и снаружи её быть не должно.
func panelAddr(cfg config.Config) string {
	if cfg.Panel.Addr != "" {
		return cfg.Panel.Addr
	}
	return "127.0.0.1:0" // 0 — пусть система даст свободный порт
}

func (rt *clientRuntime) panelURL() string {
	return "http://" + rt.addr + "/?token=" + string(rt.token)
}

// openPanel открывает панель в браузере.
func (rt *clientRuntime) openPanel() {
	url := rt.panelURL()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// rundll32, а не «start»: последний — команда оболочки, и адрес с
		// амперсандами она разрежет на части.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("браузер не открылся (%v). Панель: %s", err, url)
	}
}

// runTray держит значок и обновляет его по состоянию.
//
// Возвращается, когда значок закрыт. Цикл сообщений Win32 обязан жить в той же
// нити ОС, где создано окно, — отсюда LockOSThread.
func (rt *clientRuntime) runTray(ctx context.Context) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	t, err := tray.New(tray.Actions{
		Connect: func() {
			if err := rt.svc.Connect(ctx); err != nil {
				log.Printf("подключение: %v", err)
			}
		},
		Disconnect: func() {
			sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := rt.svc.Disconnect(sctx); err != nil {
				log.Printf("отключение: %v", err)
			}
		},
		OpenPanel: rt.openPanel,
		Quit:      func() { rt.quit() },
	})
	if err != nil {
		// Без значка клиент работать может — панель и автоподключение на месте.
		log.Printf("значок в лотке не создан: %v", err)
		<-ctx.Done()
		return
	}
	defer t.Close()

	// Всплывающие окна ОС — тем же значком.
	rt.notices.AddSink(func(e notify.Event) {
		t.Notify(string(e.Level), e.Title, e.Text)
	})

	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				t.Close()
				return
			case <-tick.C:
				t.SetState(tray.State{
					Session: sessionOf(rt.svc.Status().State),
					Unread:  rt.notices.Unread(),
				})
			}
		}
	}()

	t.Run()
}

func sessionOf(s service.State) tray.Session {
	switch s {
	case service.StateConnecting:
		return tray.Connecting
	case service.StateConnected:
		return tray.Connected
	default:
		return tray.Stopped
	}
}

// waitConnected ждёт, пока сессия установится (или истечёт срок).
//
// Нужен перед открытием браузера: сессия снимает системный прокси уже после
// того, как Connect вернулся, а браузер, запущенный в этот промежуток,
// запоминает прокси и держится за него до перезапуска.
func (rt *clientRuntime) waitConnected(ctx context.Context, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if rt.svc.Status().State == service.StateConnected {
			// Состояние меняется до того, как сессия успевает снять прокси и
			// разослать уведомление, — даём ей это доделать.
			time.Sleep(700 * time.Millisecond)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
