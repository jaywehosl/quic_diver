# live-on-tests

Боевой клиент к дублированному узлу на :27015 (localhost).
Всё вшито в .exe: адрес узла, authority, токен. Запуск — двойной клик,
клиент сам поднимается через UAC (нужны права администратора для WinDivert).

Этот узел трогать НЕ будем — стабильная точка для повседневного использования.
Разработка идёт на :443 отдельным сервером.

.exe НЕ коммитится (вшит секретный токен) — см. .gitignore.

Пересборка:
  go build -ldflags "-s -w \
    -X main.builtinServer=localhost:8443 \
    -X main.builtinAuthority=localhost \
    -X main.builtinToken=<токен>" \
    -o live-on-tests/qd-client.exe ./cmd/qd-client
