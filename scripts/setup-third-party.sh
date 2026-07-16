#!/bin/sh
# Восстанавливает пропатченный quic-go в third_party/ (в git не хранится).
#
# Что делает патч (patches/quic-go.patch):
#  1. Очереди DATAGRAM 32/128 -> 256/1024. Upstream рассчитан на редкие сигнальные
#     датаграммы: send=32 вводит отправителя в stop-and-go, rcv=128 молча дропает
#     при всплеске. У нас датаграммы несут IP-трафик, дроп = потеря пакета.
#     Больше не делаем: длинная очередь = bufferbloat.
#  2. quic.DatagramStats() — учёт принятых/дропнутых датаграмм (иначе невидимы).
#  3. Cubic вместо Reno. Upstream ХАРДКОДИТ Reno ("true, // use Reno"), а тот
#     делит окно пополам на каждой потере и растёт линейно.
#  4. brutal congestion (QD_BRUTAL_MBPS=N): слать с заданной полосой, игнорируя
#     потери. Измерено на плече 850 км: loss-based CC отдавал 458-561 Мбит при
#     потерях сети 0.016-0.27%, brutal — 694 (сырой UDP по тому же пути: 756).
#     Ставить НИЖЕ реальной полосы, иначе очереди и рост RTT.
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

patch -p1 -d "$ROOT/third_party/quic-go" < "$ROOT/patches/quic-go.patch"
echo "quic-go ${VER} пропатчен → third_party/quic-go (go.mod replace ссылается сюда)"
