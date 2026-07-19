package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"quicdiver/internal/client/config"
	"quicdiver/internal/client/control"
	"quicdiver/internal/client/notify"
	"quicdiver/internal/client/service"
	"quicdiver/internal/server/auth"
)

// --- заглушки зависимостей ---

type fakeService struct {
	mu        sync.Mutex
	state     service.State
	connErr   error
	discErr   error
	connected bool
}

func (s *fakeService) Connect(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connErr != nil {
		return s.connErr
	}
	s.connected, s.state = true, service.StateConnected
	return nil
}

func (s *fakeService) Disconnect(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discErr != nil {
		return s.discErr
	}
	s.connected, s.state = false, service.StateStopped
	return nil
}

func (s *fakeService) Status() service.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return service.Status{State: s.state}
}

type fakeControl struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	reply    string
	code     int
	err      error
	nodeSet  int
}

func (c *fakeControl) Do(ctx context.Context, r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, r)
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		c.bodies = append(c.bodies, string(b))
	}
	if c.err != nil {
		return nil, c.err
	}
	code := c.code
	if code == 0 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(c.reply)),
	}, nil
}

func (c *fakeControl) Status() control.Status { return control.Status{Online: c.err == nil} }

func (c *fakeControl) SetNode(entries []config.Entry, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodeSet++
}

type fakeConfig struct {
	mu      sync.Mutex
	cfg     config.Config
	saveErr error
	saved   int
}

func (c *fakeConfig) Get() config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func (c *fakeConfig) Save(cfg config.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.saveErr != nil {
		return c.saveErr
	}
	c.cfg, c.saved = cfg, c.saved+1
	return nil
}

// --- оснастка ---

const testToken Token = "ключ-панели"

func deps(t *testing.T) (Deps, *fakeService, *fakeControl, *fakeConfig) {
	t.Helper()
	cfg := config.Default()
	cfg.Node.Entries = []config.Entry{{Addr: "203.0.113.10:443", SNI: "node.example"}}
	cfg.Node.Token = "qd_клиент"
	cfg.Routing.Rules = []string{"dom:youtube.com=auto:de", "cidr:10.0.0.0/8=direct"}
	cfg.Routing.Default = "direct"

	svc, ctl, cf := &fakeService{}, &fakeControl{reply: `[]`}, &fakeConfig{cfg: cfg}
	return Deps{Service: svc, Control: ctl, Config: cf}, svc, ctl, cf
}

func call(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set(HeaderPanelToken, string(testToken))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// --- состояние ---

// Статус разделяет перехват и управляющую связь: сервис поднят и узел на связи
// — одно, «трафик машины идёт через узел» — другое. Трей рисует иконку по паре.
func TestStatusSeparatesSessionFromControl(t *testing.T) {
	d, _, _, _ := deps(t)
	h := Handler(testToken, d, nil)

	var st statusView
	if err := json.Unmarshal(call(t, h, http.MethodGet, "/api/status", "").Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Session != "stopped" {
		t.Fatalf("сессия: %q — перехвата ещё не включали", st.Session)
	}
	if !st.Control.Online {
		t.Fatal("управляющая связь должна жить независимо от перехвата")
	}
	if !st.Configured {
		t.Fatal("настроенный клиент помечен ненастроенным")
	}
}

// На первом запуске узла нет — панель обязана вести к настройке, а не показывать
// пустой экран с ошибкой.
func TestStatusReportsUnconfigured(t *testing.T) {
	d, _, _, cf := deps(t)
	cf.cfg.Node.Entries = nil
	cf.cfg.Node.Token = ""

	var st statusView
	json.Unmarshal(call(t, Handler(testToken, d, nil), http.MethodGet, "/api/status", "").Body.Bytes(), &st)
	if st.Configured {
		t.Fatal("пустые настройки помечены настроенными")
	}
}

func TestConnectAndDisconnect(t *testing.T) {
	d, svc, _, _ := deps(t)
	h := Handler(testToken, d, nil)

	if w := call(t, h, http.MethodPost, "/api/connect", "{}"); w.Code != http.StatusOK {
		t.Fatalf("connect: %d %s", w.Code, w.Body)
	}
	if !svc.connected {
		t.Fatal("сессия не поднята")
	}
	if w := call(t, h, http.MethodPost, "/api/disconnect", "{}"); w.Code != http.StatusOK {
		t.Fatalf("disconnect: %d %s", w.Code, w.Body)
	}
	if svc.connected {
		t.Fatal("сессия не погашена")
	}
}

// Неудачное отключение обязано быть видно: сессия возвращает системе DNS и
// прокси, и молчаливый успех оставил бы машину с нашими настройками.
func TestDisconnectFailureIsVisible(t *testing.T) {
	d, svc, _, _ := deps(t)
	svc.discErr = errors.New("не свернулась вовремя")

	w := call(t, Handler(testToken, d, nil), http.MethodPost, "/api/disconnect", "{}")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("статус %d — ошибка отключения проглочена", w.Code)
	}
	if !strings.Contains(w.Body.String(), "не свернулась") {
		t.Fatalf("причина не доехала: %s", w.Body)
	}
}

// --- настройки ---

// Битые правила не сохраняются: записанный набор оставил бы клиента без
// роутинга до ручной правки файла.
func TestBadRulesRejectedBeforeSave(t *testing.T) {
	d, _, _, cf := deps(t)
	body := `{"version":1,"routing":{"rules":["это не правило"]}}`

	w := call(t, Handler(testToken, d, nil), http.MethodPut, "/api/config", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("статус %d — битые правила приняты", w.Code)
	}
	if cf.saved != 0 {
		t.Fatal("битый конфиг сохранён")
	}
}

// Сохранение настроек сообщает управляющей связи о смене узла — иначе панель
// продолжила бы показывать данные прежнего.
func TestSaveNotifiesControl(t *testing.T) {
	d, _, ctl, cf := deps(t)
	body := `{"version":1,"node":{"token":"qd_новый","entries":[{"addr":"198.51.100.7:443"}]},"routing":{"rules":["dom:a.example=direct"]}}`

	if w := call(t, Handler(testToken, d, nil), http.MethodPut, "/api/config", body); w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if cf.saved != 1 {
		t.Fatal("конфиг не сохранён")
	}
	if ctl.nodeSet == 0 {
		t.Fatal("управляющая связь не узнала о смене узла")
	}
}

// --- тестер правил ---

func testRuleCall(t *testing.T, h http.Handler, body string) testResult {
	t.Helper()
	w := call(t, h, http.MethodPost, "/api/rules/test", body)
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	var res testResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// Главная фича панели: видно не только куда пойдёт трафик, но и КАКОЕ правило
// сработало. Иначе «почему пошло не туда» выясняется на живом трафике.
func TestRuleTesterNamesTheRule(t *testing.T) {
	d, _, _, _ := deps(t)
	res := testRuleCall(t, Handler(testToken, d, nil), `{"host":"rr1.youtube.com"}`)

	if res.Out != "auto:de" {
		t.Fatalf("выход %q", res.Out)
	}
	if res.Rule != 1 || !strings.Contains(res.RuleText, "youtube") {
		t.Fatalf("правило не названо: %+v", res)
	}
	if res.Default {
		t.Fatal("помечено выходом по умолчанию, хотя правило сработало")
	}
}

// Не совпало ни одно — так и говорим, а не выдаём «правило 0».
func TestRuleTesterReportsDefault(t *testing.T) {
	d, _, _, _ := deps(t)
	res := testRuleCall(t, Handler(testToken, d, nil), `{"host":"example.org"}`)

	if !res.Default || res.Rule != 0 || res.Out != "direct" {
		t.Fatalf("выход по умолчанию не отмечен: %+v", res)
	}
}

// IP и домен — разные условия. Введённый IP не должен матчиться доменным
// правилом, и наоборот.
func TestRuleTesterHandlesIPAndDomain(t *testing.T) {
	d, _, _, _ := deps(t)
	h := Handler(testToken, d, nil)

	if res := testRuleCall(t, h, `{"host":"10.1.2.3"}`); res.Rule != 2 {
		t.Fatalf("правило по подсети не сработало: %+v", res)
	}
	// Домен не должен попадать в правило по подсети на нулевом адресе.
	if res := testRuleCall(t, h, `{"host":"example.org"}`); res.Rule != 0 {
		t.Fatalf("домен поймался правилом по подсети: %+v", res)
	}
}

// Про per-app честно предупреждаем: правило принимается, но на живом трафике
// имя процесса не определяется. Молча делать вид, что работает, — хуже.
func TestRuleTesterWarnsAboutProcessRules(t *testing.T) {
	d, _, _, cf := deps(t)
	cf.cfg.Routing.Rules = append([]string{"proc:chrome.exe=direct"}, cf.cfg.Routing.Rules...)

	res := testRuleCall(t, Handler(testToken, d, nil), `{"host":"example.org"}`)
	if res.Note == "" || !strings.Contains(res.Note, "процесс") {
		t.Fatalf("нет предупреждения о правилах по процессу: %+v", res)
	}
}

// --- прокси в админ-API узла ---

// Без админ-токена в узел не ходим.
func TestProxyRequiresAdminToken(t *testing.T) {
	d, _, ctl, _ := deps(t)
	w := call(t, Handler(testToken, d, nil), http.MethodGet, "/api/node/qd-admin/users", "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("статус %d", w.Code)
	}
	if len(ctl.requests) != 0 {
		t.Fatal("запрос ушёл на узел без админ-токена")
	}
}

// Админ-токен уходит на узел заголовком и не подмешивается в конфиг клиента:
// хранить ключ от всей сети рядом с клиентским токеном нельзя.
func TestProxyForwardsAdminToken(t *testing.T) {
	d, _, ctl, cf := deps(t)
	h := Handler(testToken, d, nil)

	r := httptest.NewRequest(http.MethodGet, "/api/node/qd-admin/users?hash=abc", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set(HeaderPanelToken, string(testToken))
	r.Header.Set(auth.HeaderToken, "qd_админ")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if len(ctl.requests) != 1 {
		t.Fatalf("запросов к узлу: %d", len(ctl.requests))
	}
	sent := ctl.requests[0]
	if got := sent.Header.Get(auth.HeaderToken); got != "qd_админ" {
		t.Fatalf("админ-токен не передан: %q", got)
	}
	if !strings.HasSuffix(sent.URL.Path, "/qd-admin/users") || sent.URL.RawQuery != "hash=abc" {
		t.Fatalf("путь искажён: %s?%s", sent.URL.Path, sent.URL.RawQuery)
	}
	if cf.cfg.Node.Token == "qd_админ" {
		t.Fatal("админ-токен просочился в конфиг клиента")
	}
}

// Недоступный узел — понятная ошибка, а не пустой ответ.
func TestProxyReportsNodeDown(t *testing.T) {
	d, _, ctl, _ := deps(t)
	ctl.err = errors.New("узел недоступен")

	r := httptest.NewRequest(http.MethodGet, "/api/node/qd-admin/stats", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set(HeaderPanelToken, string(testToken))
	r.Header.Set(auth.HeaderToken, "qd_админ")
	w := httptest.NewRecorder()
	Handler(testToken, d, nil).ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("статус %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "недоступен") {
		t.Fatalf("причина не доехала: %s", w.Body)
	}
}

// Список выходов берётся через управляющую связь — он нужен ДО подключения,
// иначе правило пришлось бы писать вслепую.
func TestExitsGoThroughControl(t *testing.T) {
	d, _, ctl, _ := deps(t)
	ctl.reply = `[{"route":"direct"},{"route":"auto:de"}]`

	w := call(t, Handler(testToken, d, nil), http.MethodGet, "/api/exits", "")
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "auto:de") {
		t.Fatalf("список выходов не доехал: %s", w.Body)
	}
	if len(ctl.requests) != 1 || !strings.HasSuffix(ctl.requests[0].URL.Path, "/qd-exits") {
		t.Fatalf("запрос ушёл не туда: %+v", ctl.requests)
	}
}

// Метод, которого эндпоинт не ждёт, отклоняется: изменяющая операция на GET
// прошла бы мимо защиты от чужих страниц.
func TestWrongMethodRejected(t *testing.T) {
	d, _, _, _ := deps(t)
	h := Handler(testToken, d, nil)

	if w := call(t, h, http.MethodGet, "/api/connect", ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("connect по GET: статус %d", w.Code)
	}
	if w := call(t, h, http.MethodPost, "/api/status", "{}"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status по POST: статус %d", w.Code)
	}
}

// --- уведомления ---

// Панель показывает уведомления и счётчик непрочитанных: по счётчику трей
// красит иконку, и разбирать ради него весь список он не должен.
func TestNotificationsListed(t *testing.T) {
	d, _, _, _ := deps(t)
	c := notify.New()
	c.Post(notify.Warn, "узел недоступен", "de.example")
	c.Post(notify.Info, "узел сменился", "")
	d.Notices = c

	w := call(t, Handler(testToken, d, nil), http.MethodGet, "/api/notifications", "")
	var v noticesView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Unread != 2 || len(v.Items) != 2 {
		t.Fatalf("уведомления: %+v", v)
	}
	if v.Items[0].Title != "узел сменился" {
		t.Fatalf("порядок не от свежих: %+v", v.Items)
	}
}

// Прочитанное перестаёт красить иконку.
func TestNotificationsMarkedRead(t *testing.T) {
	d, _, _, _ := deps(t)
	c := notify.New()
	c.Post(notify.Warn, "первое", "")
	c.Post(notify.Warn, "второе", "")
	d.Notices = c
	h := Handler(testToken, d, nil)

	w := call(t, h, http.MethodPost, "/api/notifications", `{"id":0}`)
	var v noticesView
	json.Unmarshal(w.Body.Bytes(), &v)
	if v.Unread != 0 {
		t.Fatalf("после отметки всех непрочитанных: %d", v.Unread)
	}
	if len(v.Items) != 2 {
		t.Fatal("отметка прочитанным не должна удалять уведомления")
	}
}

// Очистка убирает список целиком.
func TestNotificationsCleared(t *testing.T) {
	d, _, _, _ := deps(t)
	c := notify.New()
	c.Post(notify.Error, "нет связи", "")
	d.Notices = c

	w := call(t, Handler(testToken, d, nil), http.MethodPost, "/api/notifications", `{"clear":true}`)
	var v noticesView
	json.Unmarshal(w.Body.Bytes(), &v)
	if len(v.Items) != 0 || v.Unread != 0 {
		t.Fatalf("очистка не сработала: %+v", v)
	}
}

// Панель без подключённых уведомлений не падает: список просто пуст.
func TestNotificationsAbsentIsEmpty(t *testing.T) {
	d, _, _, _ := deps(t)
	w := call(t, Handler(testToken, d, nil), http.MethodGet, "/api/notifications", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
}

// Комментарии и пустые строки правилами не становятся, поэтому нумерация
// набора и нумерация строк редактора расходятся. Тестер обязан показывать
// СТРОКУ: человек смотрит в тот же текст, и «правило №2» отправило бы его не
// туда. Поймано на живых данных — юнит-тест без комментариев этого не видел.
func TestRuleTesterPointsAtEditorLine(t *testing.T) {
	d, _, _, cf := deps(t)
	cf.cfg.Routing.Rules = []string{
		"# банк мимо туннеля",
		"dom:bank.example = direct",
		"",
		"dom:youtube.com = auto:de",
	}

	res := testRuleCall(t, Handler(testToken, d, nil), `{"host":"rr1.youtube.com"}`)
	if res.Out != "auto:de" {
		t.Fatalf("выход %q", res.Out)
	}
	if res.Rule != 4 {
		t.Fatalf("строка %d, ожидалась 4 (комментарий и пустая строка не правила)", res.Rule)
	}
	if !strings.Contains(res.RuleText, "youtube") {
		t.Fatalf("текст правила: %q", res.RuleText)
	}
}
