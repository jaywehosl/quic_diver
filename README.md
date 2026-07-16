# QUIC Diver

Прозрачный TUN-less прокси. Единое Go-ядро на всех ОС (кроме захвата пакетов).
Транспорт клиент↔узел — QUIC + MASQUE. Выбранная модель data-path — **B (connect-ip)**:
клиент тонкий (заворачивает сырые IP в connect-ip датаграммы), gVisor+netstack живёт
на узле. Каркас спроектирован так, что модель **A** (терминация L4 в gVisor на клиенте)
добавляется позже без переделки — вся развилка заперта в `engine.Engine`.

## Ключевые контракты

| Пакет | Контракт | Роль |
|-------|----------|------|
| `internal/packet` | `Source` | batch recv/send сырых IP; WinDivert (Win) / TUN (проч.) |
| `internal/uplink` | `Conn`, `Dialer` | QUIC/H3 до узла; datagram+stream; миграция (arch4) |
| `internal/engine` | `Engine` | модель обработки; B=`connectip`, A=позже |
| `internal/routing` | `Router` | direct \| chain \| block по 5-tuple |
| `internal/guard` | `Guard` | local-guard: не захватывать локалку + анти-петля (arch5) |
| `internal/auth` | `Authenticator` | токен внутри H3, decoy fallback |
| `internal/server/db` | `Store` | SQLite; backup/restore (arch3) |
| `internal/server/decoy` | — | "under construction" :443, база веб-панели |

## Узел = master/slave

Один бинарь `qd-server`. Роль определяется конфигом/наличием БД, не кодом.
Единый admin-токен коннектится к любому узлу. Chain = узел дозванивается до upstream-узла.

## Статус

Каркас: интерфейсы + скелеты, stdlib-only, компилируется офлайн.
Внешние зависимости (quic-go, masque-go, gvisor, WinDivert-биндинг) подключаются на шаге PoC.

## Сборка

```
go build ./...
```

Релизный клиент — один `.exe`: web-панель (`embed.FS`) и WinDivert `.dll`/`.sys` вшиты,
распаковка в `%APPDATA%\QUICDiver`.
