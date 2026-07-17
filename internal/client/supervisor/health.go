package supervisor

import (
	"context"
	"log"
	"net"
	"net/netip"
	"time"

	"quicdiver/internal/client/netwatch"
)

// Детект мёртвого пути и починка миграцией.
//
// Самый частый обрыв — не смена сети у клиента, а разрыв МЕЖДУ РОУТЕРОМ И
// ПРОВАЙДЕРОМ (PPPoE пересобрался, LTE моргнула). Локальный адрес при этом не
// меняется вовсе: линк ПК↔роутер цел. Смена адреса такое не ловит по построению.
//
// Что при этом происходит: пока роутер восстанавливает связь, наши пакеты уходят
// в никуда. Если связь вернулась быстро — QUIC доретрансмитит сам, вмешиваться не
// надо. Но роутер, пересобрав соединение, обычно заводит НОВУЮ таблицу NAT: наш
// маппинг исчез, ответы узла больше не находят дорогу назад, и сессия висит
// мёртвой до idle-таймаута, хотя сеть уже работает.
//
// Лечение: заметив тишину в приёме при том, что сами продолжаем слать, переезжаем
// на новый локальный порт. Роутер заводит для него свежий маппинг, узел
// подтверждает путь (PATH_CHALLENGE/PATH_RESPONSE) — связь возвращается за один
// RTT, а не за десятки секунд. Пока сеть лежит, попытка просто не удаётся;
// повторяем, и первая же после возврата связи срабатывает.
//
// Сессия и её стримы при этом целы: TCP приложений не рвётся — ровно то, ради
// чего arch4 и существует.

// watchPath следит за счётчиками и чинит путь. Блокируется до отмены ctx.
func (s *Supervisor) watchPath(ctx context.Context) {
	t := time.NewTicker(s.cfg.ProbeEvery)
	defer t.Stop()

	var (
		lastSent, lastRecv uint64
		silentSince        time.Time
		lastRepair         time.Time
		tries              int // попыток за текущий обрыв
		started            bool
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		sent, recv := s.cfg.Client.Traffic()
		if !started {
			lastSent, lastRecv, started = sent, recv, true
			continue
		}

		switch {
		case recv > lastRecv:
			// ответы идут — путь жив
			if !silentSince.IsZero() {
				log.Printf("supervisor: путь ожил (тишина длилась %v)",
					time.Since(silentSince).Round(time.Second))
			}
			silentSince = time.Time{}
			tries = 0 // обрыв кончился: следующему дать полный запас попыток
		case sent > lastSent:
			// шлём, а в ответ ничего: либо сеть лежит, либо маппинг слетел
			if silentSince.IsZero() {
				silentSince = time.Now()
			}
		default:
			// молчим оба — обычный простой, не повод дёргаться
		}
		lastSent, lastRecv = sent, recv

		if silentSince.IsZero() || time.Since(silentSince) < s.cfg.SilenceLimit {
			continue
		}
		if time.Since(lastRepair) < s.cfg.RepairEvery {
			continue // не долбить: сеть могла ещё не подняться
		}
		if s.cfg.MaxRepairs >= 0 && tries >= s.cfg.MaxRepairs {
			// Запас connection ID кончился бы, а без них переезд невозможен даже
			// после возврата связи. Дальше не мешаем: сессия умрёт по
			// idle-таймауту, и туннель поднимут заново — редайлу ID не нужны.
			continue
		}
		lastRepair = time.Now()
		tries++
		s.repair(ctx)
	}
}

// repair переносит сессию на новый локальный порт, чтобы роутер завёл свежий
// NAT-маппинг. Адрес берём текущий: он мог и не меняться — важен именно порт.
func (s *Supervisor) repair(ctx context.Context) {
	addr, err := s.localAddr()
	if err != nil {
		return // сети сейчас нет вовсе — чинить нечего, ждём
	}
	mctx, cancel := context.WithTimeout(ctx, s.cfg.MigrateTimeout)
	err = s.cfg.Client.Migrate(mctx, &net.UDPAddr{IP: addr.AsSlice(), Port: 0})
	cancel()

	s.mu.Lock()
	s.repairs++
	if err != nil {
		s.repairFails++
	}
	s.mu.Unlock()

	if err != nil {
		// Пока сеть не вернулась, неудача — норма. Но совсем молчать нельзя: если
		// починка не срабатывает по другой причине (например, узел не даёт новых
		// connection ID), это единственный след. Первые попытки и дальше изредка.
		if n := s.repairFailsSnapshot(); n <= 2 || n%10 == 0 {
			log.Printf("supervisor: починка пути не удалась (%d-я): %v", n, err)
		}
		return
	}
	log.Printf("supervisor: путь был мёртв — переехали на новый порт с %s, связь восстановлена", addr)
}

// localAddr — с какого адреса переезжать. По умолчанию текущий исходящий адрес
// машины; в тестах и на нестандартных стендах задаётся через Config.LocalAddr.
func (s *Supervisor) localAddr() (netip.Addr, error) {
	if s.cfg.LocalAddr != nil {
		return s.cfg.LocalAddr()
	}
	st, err := netwatch.Current(func() bool { return false })
	if err != nil {
		return netip.Addr{}, err
	}
	return st.Primary, nil
}

// repairFailsSnapshot — сколько починок уже не удалось.
func (s *Supervisor) repairFailsSnapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repairFails
}
