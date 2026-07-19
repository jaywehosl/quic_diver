//go:build windows

package tray

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Значок и меню на Win32 напрямую, без cgo и внешних библиотек: релизный
// клиент по ТЗ — один exe без зависимостей, и тянуть ради лотка C-тулчейн
// значило бы этому противоречить.
var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessage      = user32.NewProc("PostMessageW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procCreateIcon       = user32.NewProc("CreateIcon")
	procDestroyIcon      = user32.NewProc("DestroyIcon")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy  = 0x0002
	wmClose    = 0x0010
	wmCommand  = 0x0111
	wmUser     = 0x0400
	wmTrayIcon = wmUser + 1
	wmRightUp  = 0x0205
	wmLeftUp   = 0x0202
	wmLeftDbl  = 0x0203

	nimAdd    = 0x0000
	nimModify = 0x0001
	nimDelete = 0x0002

	nifMessage = 0x0001
	nifIcon    = 0x0002
	nifTip     = 0x0004
	nifInfo    = 0x0010

	niifInfo    = 0x0001
	niifWarning = 0x0002
	niifError   = 0x0003

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfGrayed    = 0x0001

	tpmRightButton = 0x0002

	idConnect    = 1
	idDisconnect = 2
	idPanel      = 3
	idQuit       = 4
)

// Actions — что делает меню значка.
type Actions struct {
	Connect    func()
	Disconnect func()
	OpenPanel  func()
	Quit       func()
}

// Tray — значок в лотке.
type Tray struct {
	hwnd    windows.Handle
	actions Actions

	mu    sync.Mutex
	state State
	icons map[Look]windows.Handle
	added bool
}

type notifyIconData struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

// New создаёт значок. Возвращается сразу; Run крутит цикл сообщений.
func New(a Actions) (*Tray, error) {
	t := &Tray{actions: a, icons: map[Look]windows.Handle{}}
	if err := t.createWindow(); err != nil {
		return nil, err
	}
	if err := t.add(); err != nil {
		return nil, err
	}
	return t, nil
}

// createWindow заводит невидимое окно — приёмник сообщений лотка.
//
// Своего окна у сервиса нет, а Shell_NotifyIcon шлёт события именно окну.
func (t *Tray) createWindow() error {
	inst, _, _ := procGetModuleHandle.Call(0)
	class := windows.StringToUTF16Ptr("QuicDiverTray")

	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   syscall.NewCallback(t.wndProc),
		HInstance:     windows.Handle(inst),
		LpszClassName: class,
	}
	if ret, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); ret == 0 {
		return fmt.Errorf("tray: регистрация класса окна: %w", err)
	}
	hwnd, _, err := procCreateWindowEx.Call(
		0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(class)),
		0, 0, 0, 0, 0, 0, 0, inst, 0)
	if hwnd == 0 {
		return fmt.Errorf("tray: создание окна: %w", err)
	}
	t.hwnd = windows.Handle(hwnd)
	return nil
}

// wndProc обрабатывает сообщения окна.
func (t *Tray) wndProc(hwnd windows.Handle, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmTrayIcon:
		switch uint32(lParam) {
		case wmRightUp:
			t.showMenu()
		case wmLeftDbl, wmLeftUp:
			// Левый клик — самое частое действие, и это открыть панель.
			if t.actions.OpenPanel != nil {
				go t.actions.OpenPanel()
			}
		}
		return 0
	case wmCommand:
		t.command(uint16(wParam))
		return 0
	case wmClose:
		procDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
	return ret
}

func (t *Tray) command(id uint16) {
	// В отдельной горутине: обработчик держит очередь сообщений окна, и
	// подключение на нём подвесило бы весь значок вместе с меню.
	var fn func()
	switch id {
	case idConnect:
		fn = t.actions.Connect
	case idDisconnect:
		fn = t.actions.Disconnect
	case idPanel:
		fn = t.actions.OpenPanel
	case idQuit:
		fn = t.actions.Quit
	}
	if fn != nil {
		go fn()
	}
}

// showMenu рисует меню у курсора.
func (t *Tray) showMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	t.mu.Lock()
	connected := t.state.Session == Connected || t.state.Session == Connecting
	t.mu.Unlock()

	// Недоступный пункт показываем серым, а не прячем: исчезающие пункты меню
	// заставляют искать то, что было здесь секунду назад.
	add := func(id uintptr, text string, enabled bool) {
		flags := uintptr(mfString)
		if !enabled {
			flags |= mfGrayed
		}
		procAppendMenu.Call(menu, flags, id,
			uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))))
	}
	add(idConnect, "Подключиться", !connected)
	add(idDisconnect, "Отключиться", connected)
	procAppendMenu.Call(menu, mfSeparator, 0, 0)
	add(idPanel, "Открыть панель", true)
	procAppendMenu.Call(menu, mfSeparator, 0, 0)
	add(idQuit, "Выйти", true)

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Без этого меню не закрывается по клику мимо — известная особенность
	// всплывающих меню у окон без фокуса.
	procSetForegroundWin.Call(uintptr(t.hwnd))
	procTrackPopupMenu.Call(menu, tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
	procPostMessage.Call(uintptr(t.hwnd), 0, 0, 0)
}

// add показывает значок.
func (t *Tray) add() error {
	data := t.baseData()
	data.UFlags = nifMessage | nifIcon | nifTip
	data.UCallbackMessage = wmTrayIcon
	data.HIcon = t.icon(Grey)
	copyUTF16(data.SzTip[:], Hint(State{}))

	if ret, _, err := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(data))); ret == 0 {
		return fmt.Errorf("tray: значок не добавлен: %w", err)
	}
	t.mu.Lock()
	t.added = true
	t.mu.Unlock()
	return nil
}

// SetState перерисовывает значок под новое состояние.
func (t *Tray) SetState(s State) {
	t.mu.Lock()
	if t.state == s || !t.added {
		t.state = s
		t.mu.Unlock()
		return
	}
	t.state = s
	t.mu.Unlock()

	data := t.baseData()
	data.UFlags = nifIcon | nifTip
	data.HIcon = t.icon(LookOf(s))
	copyUTF16(data.SzTip[:], Hint(s))
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(data)))
}

// Notify показывает всплывающее уведомление у значка.
func (t *Tray) Notify(level, title, text string) {
	data := t.baseData()
	data.UFlags = nifInfo
	copyUTF16(data.SzInfoTitle[:], title)
	copyUTF16(data.SzInfo[:], text)
	switch level {
	case "error":
		data.DwInfoFlags = niifError
	case "warn":
		data.DwInfoFlags = niifWarning
	default:
		data.DwInfoFlags = niifInfo
	}
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(data)))
}

// Run крутит цикл сообщений до закрытия значка.
//
// Обязан идти в той же нити ОС, где создано окно, — отсюда LockOSThread у
// вызывающего.
func (t *Tray) Run() {
	defer t.cleanup()

	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// Close убирает значок и останавливает цикл сообщений.
//
// Вызывается ИЗ ЛЮБОЙ нити, поэтому окно закрывается сообщением, а не прямым
// DestroyWindow: Windows выполняет уничтожение только в той нити, что окно
// создала, — из чужой вызов молча ничего не делает. Цикл сообщений тогда висит
// вечно, и процесс не завершается после «Выйти». Наступали на это вживую.
func (t *Tray) Close() {
	t.mu.Lock()
	hwnd, added := t.hwnd, t.added
	t.mu.Unlock()

	// Значок снимаем сразу: иначе он остаётся в лотке призраком до наведения
	// мыши. Эта операция нити не требует.
	if added {
		t.mu.Lock()
		t.added = false
		t.mu.Unlock()
		data := t.baseData()
		procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(data)))
	}
	if hwnd != 0 {
		procPostMessage.Call(uintptr(hwnd), wmClose, 0, 0)
	}
}

// cleanup освобождает то, что можно трогать только из нити окна. Вызывается
// самим циклом сообщений на выходе.
func (t *Tray) cleanup() {
	t.mu.Lock()
	added := t.added
	t.added = false
	icons := t.icons
	t.icons = map[Look]windows.Handle{}
	t.mu.Unlock()

	if added {
		data := t.baseData()
		procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(data)))
	}
	for _, h := range icons {
		procDestroyIcon.Call(uintptr(h))
	}
}

func (t *Tray) baseData() *notifyIconData {
	return &notifyIconData{
		CbSize: uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:   t.hwnd,
		UID:    1,
	}
}

func copyUTF16(dst []uint16, s string) {
	src := windows.StringToUTF16(s)
	if len(src) > len(dst) {
		src = src[:len(dst)-1]
		src = append(src, 0)
	}
	copy(dst, src)
}
