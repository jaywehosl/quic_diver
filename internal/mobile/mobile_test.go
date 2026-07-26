package mobile

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMobileEngineLifecycle(t *testing.T) {
	// Создаем виртуальную пару сокетов для имитации TUN fd
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// 1. Проверяем начальный статус
	stJson := GetStatus()
	var st MobileStatus
	if err := json.Unmarshal([]byte(stJson), &st); err != nil {
		t.Fatalf("Unmarshal initial status: %v", err)
	}
	if st.Connected {
		t.Errorf("expected disconnected initially")
	}

	// 2. Старт мобильного движка
	rules := "dom:youtube.com = auto:de\nproc:chrome.exe = direct"
	if err := StartEngine(int(r.Fd()), "127.0.0.1:8443", "test_token", rules); err != nil {
		t.Fatalf("StartEngine failed: %v", err)
	}

	// 3. Повторный запуск должен вернуть ошибку
	if err := StartEngine(int(r.Fd()), "127.0.0.1:8443", "test_token", rules); err == nil {
		t.Errorf("expected error on double StartEngine")
	}

	// 4. Проверяем статус работы
	stJson = GetStatus()
	if err := json.Unmarshal([]byte(stJson), &st); err != nil {
		t.Fatalf("Unmarshal active status: %v", err)
	}
	if !st.Connected || st.Server != "127.0.0.1:8443" {
		t.Errorf("unexpected active status: %+v", st)
	}

	// 5. Динамическое обновление правил
	newRules := "dom:discord.gg = auto:de"
	if err := UpdateRules(newRules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	// 6. Остановка движка
	if err := StopEngine(); err != nil {
		t.Fatalf("StopEngine failed: %v", err)
	}

	// 7. Итоговый статус — отключено
	stJson = GetStatus()
	if err := json.Unmarshal([]byte(stJson), &st); err != nil {
		t.Fatalf("Unmarshal stopped status: %v", err)
	}
	if st.Connected {
		t.Errorf("expected disconnected after StopEngine")
	}
}
