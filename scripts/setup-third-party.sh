#!/bin/sh
# Восстанавливает пропатченный quic-go в third_party/ (в git не хранится).
#
# Зачем патч: upstream-очереди DATAGRAM рассчитаны на редкие сигнальные датаграммы
# (send=32 блокирует отправителя, rcv=128 молча дропает при burst). У нас датаграммы
# несут ВЕСЬ IP-трафик: дроп = потеря пакета = внутренний TCP рушит cwnd. Патч
# поднимает очереди до 256/1024 (не больше — длинная очередь даёт bufferbloat) и
# добавляет quic.DatagramStats() для учёта дропов.
#
# Запуск: sh scripts/setup-third-party.sh
set -e

VER="v0.60.0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOD="$(go env GOMODCACHE)/github.com/quic-go/quic-go@${VER}"

if [ ! -d "$MOD" ]; then
	echo "качаю quic-go ${VER}..."
	(cd "$ROOT" && go mod download github.com/quic-go/quic-go)
fi
[ -d "$MOD" ] || { echo "нет модуля: $MOD" >&2; exit 1; }

rm -rf "$ROOT/third_party/quic-go"
mkdir -p "$ROOT/third_party"
cp -r "$MOD" "$ROOT/third_party/quic-go"
chmod -R u+w "$ROOT/third_party/quic-go"

patch -p1 -d "$ROOT/third_party/quic-go" < "$ROOT/patches/quic-go-datagram.patch"
echo "quic-go ${VER} пропатчен → third_party/quic-go (go.mod replace ссылается сюда)"
