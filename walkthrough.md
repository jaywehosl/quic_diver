# Результаты обновления веб-панели управления, пула настроек клиента и логирования

## 1. 🔑 Персистентная сессия в веб-панели (без запроса токена при F5)
- Токен веб-панели и админ-токен сохраняются в `localStorage` браузера (`qd_panel_token` и `qd_admin_token`).
- При нажатии `F5` или повторном открытии вкладки браузер автоматически восстанавливает авторизацию и загружает панель управления без повторного вызова формы логина.

---

## 2. ⚙️ Пул локальных настроек клиента
- **BRUTAL Скорость (`transport.brutal_mbps`)**:
  - Установлено значение по умолчанию **`700` Мбит/с** ([config.go](file:///c:/Users/jaywehosl/Desktop/quic-diver/internal/client/config/config.go#L149)).
- **Автоподключение при старте (`autoconnect`)**:
  - По умолчанию **выключено** (`false`).
- **Автозапуск с ОС (`autostart`)**:
  - По умолчанию **выключен** (`false`).
  - При включении прописывает путь к клиентскому сервису в ветку реестра Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\QUICDiver` ([autostart_windows.go](file:///c:/Users/jaywehosl/Desktop/quic-diver/internal/client/config/autostart_windows.go)).
- **Файловый лог и цикличная ротация (`logging`)**:
  - **Включение**: по умолчанию **выключено** (`false`).
  - **Размер лог-файла**: по умолчанию **`1` МБ** (`max_mb = 1`). При превышении 1 МБ лог циклически сбрасывается и перезаписывается, не раздувая диск.
  - **Уровень лога**: по умолчанию **`info`** (рабочий режим; также доступны `debug` и `trace`).

---

## 3. 🖥️ Управление из Веб-панели и Трей-меню
- Добавлены новые элементы управления в интерфейсе вкладки «Узел и доступ» в [index.html](file:///c:/Users/jaywehosl/Desktop/quic-diver/internal/client/panel/ui/index.html) и [app.js](file:///c:/Users/jaywehosl/Desktop/quic-diver/internal/client/panel/ui/app.js).
- Консоль не выводит отладочный шум; работа со связью производится либо из веб-панели, либо из контекстного меню в системном трее Windows.

---

## 4. 🧪 Результаты тестов
- `go test -v ./internal/client/config/...` — **PASS**.
- `go test -v ./internal/client/api/...` — **PASS**.
- Полный прогон `go test ./...` — **100% PASS**.
