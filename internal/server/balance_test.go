package server

import (
	"testing"
	"time"
)

// ms — короткая запись длительности в тестах.
func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// clock — управляемое время: пороги балансировщика измеряются минутами, ждать
// их по-настоящему в тестах нельзя.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func testBalancer() (*balancer, *clock) {
	c := &clock{t: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)}
	b := newBalancer()
	b.nowFunc = c.now
	return b, c
}

// win прогоняет столько окон, сколько нужно для устойчивого преимущества,
// обновляя метрики каждое окно — так же, как это делает реальный опрос связей.
func win(b *balancer, c *clock, tag string, candidates []string, keep map[string]PathStats) string {
	var got string
	for i := 0; i < holdWindows; i++ {
		for node, st := range keep {
			b.Observe(node, st)
		}
		got = b.Pick(tag, candidates)
		c.add(pollStats)
	}
	return got
}

// Первый выбор — сразу лучший: ждать «устойчивости» не с чем, альтернативы нет.
func TestPicksBestImmediatelyOnFirstChoice(t *testing.T) {
	b, _ := testBalancer()
	b.Observe("slow", PathStats{SRTT: ms(200)})
	b.Observe("fast", PathStats{SRTT: ms(20)})

	if got := b.Pick("de", []string{"slow", "fast"}); got != "fast" {
		t.Fatalf("выбран %q, ожидался fast", got)
	}
}

// Ровный узел выигрывает у «быстрого, но рваного»: по одному среднему они
// неразличимы, и балансировщик уехал бы на дёрганый.
func TestSteadyBeatsJittery(t *testing.T) {
	b, _ := testBalancer()
	// 20±40 против стабильных 30: score 100 против 30.
	b.Observe("jittery", PathStats{SRTT: ms(20), RTTVar: ms(40)})
	b.Observe("steady", PathStats{SRTT: ms(30), RTTVar: ms(0)})

	if got := b.Pick("de", []string{"jittery", "steady"}); got != "steady" {
		t.Fatalf("выбран %q, ожидался steady", got)
	}
}

// Потери бьют по скорости сильнее лишних миллисекунд: узел с 1% потерь должен
// проигрывать более медленному, но чистому.
func TestLossOutweighsLatency(t *testing.T) {
	b, _ := testBalancer()
	b.Observe("lossy", PathStats{SRTT: ms(30), Loss: 0.01}) // 30 + 20 = 50
	b.Observe("clean", PathStats{SRTT: ms(40)})             // 40

	if got := b.Pick("de", []string{"lossy", "clean"}); got != "clean" {
		t.Fatalf("выбран %q, ожидался clean", got)
	}
}

// Мелкий выигрыш переключения не стоит: разрыв флоу дороже пары миллисекунд.
func TestIgnoresMarginalGain(t *testing.T) {
	b, c := testBalancer()
	b.Observe("cur", PathStats{SRTT: ms(100)})
	b.Observe("other", PathStats{SRTT: ms(200)})
	if got := b.Pick("de", []string{"cur", "other"}); got != "cur" {
		t.Fatalf("первый выбор: %q", got)
	}
	c.add(switchCooldown + time.Minute)

	// 100 → 90: выигрыш 10%, порога в 20% не берёт.
	keep := map[string]PathStats{"cur": {SRTT: ms(100)}, "other": {SRTT: ms(90)}}
	if got := win(b, c, "de", []string{"cur", "other"}, keep); got != "cur" {
		t.Fatalf("переключился на выигрыш 10%%: %q", got)
	}
}

// На очень низких RTT относительный порог берётся легко, поэтому нужен ещё и
// абсолютный: иначе балансировщик дёргался бы на шуме измерений.
func TestIgnoresTinyAbsoluteGain(t *testing.T) {
	b, c := testBalancer()
	b.Observe("cur", PathStats{SRTT: 4 * time.Millisecond})
	b.Observe("other", PathStats{SRTT: 50 * time.Millisecond})
	b.Pick("de", []string{"cur", "other"})
	c.add(switchCooldown + time.Minute)

	// 4 мс → 1 мс: выигрыш 75%, но абсолютная разница всего 3 мс.
	keep := map[string]PathStats{"cur": {SRTT: 4 * time.Millisecond}, "other": {SRTT: 1 * time.Millisecond}}
	if got := win(b, c, "de", []string{"cur", "other"}, keep); got != "cur" {
		t.Fatalf("переключился на разницу 3 мс: %q", got)
	}
}

// Устойчивое преимущество — переключаемся. Но не раньше, чем оно подтвердится
// несколькими окнами подряд: разовая удача выходом не считается.
func TestSwitchesOnSustainedAdvantage(t *testing.T) {
	b, c := testBalancer()
	b.Observe("cur", PathStats{SRTT: ms(200)})
	b.Observe("other", PathStats{SRTT: ms(300)})
	b.Pick("de", []string{"cur", "other"})
	c.add(switchCooldown + time.Minute)

	nodes := []string{"cur", "other"}
	for i := 1; i < holdWindows; i++ {
		b.Observe("cur", PathStats{SRTT: ms(200)})
		b.Observe("other", PathStats{SRTT: ms(50)}) // вчетверо быстрее
		if got := b.Pick("de", nodes); got != "cur" {
			t.Fatalf("окно %d: переключился раньше срока (%q)", i, got)
		}
		c.add(pollStats)
	}
	b.Observe("cur", PathStats{SRTT: ms(200)})
	b.Observe("other", PathStats{SRTT: ms(50)})
	if got := b.Pick("de", nodes); got != "other" {
		t.Fatalf("устойчивое преимущество не сработало: %q", got)
	}
}

// Сразу после переключения — пауза: без неё два близких узла устроили бы
// пинг-понг, а каждый переезд рвёт новые флоу.
func TestCooldownBlocksImmediateSwitchBack(t *testing.T) {
	b, c := testBalancer()
	b.Observe("a", PathStats{SRTT: ms(200)})
	b.Observe("b", PathStats{SRTT: ms(300)})
	b.Pick("de", []string{"a", "b"})
	c.add(switchCooldown + time.Minute)

	bWins := map[string]PathStats{"a": {SRTT: ms(200)}, "b": {SRTT: ms(50)}}
	if got := win(b, c, "de", []string{"a", "b"}, bWins); got != "b" {
		t.Fatalf("не переключился: %q", got)
	}
	// Теперь резко лучше стал прежний — но cooldown ещё идёт.
	aWins := map[string]PathStats{"a": {SRTT: ms(1)}, "b": {SRTT: ms(50)}}
	if got := win(b, c, "de", []string{"a", "b"}, aWins); got != "b" {
		t.Fatalf("переключился внутри cooldown: %q", got)
	}
	c.add(switchCooldown)
	if got := win(b, c, "de", []string{"a", "b"}, aWins); got != "a" {
		t.Fatalf("после cooldown не переключился: %q", got)
	}
}

// Прерванное преимущество копится заново: кандидат, выигравший через раз,
// устойчивым не является.
func TestInterruptedAdvantageResets(t *testing.T) {
	b, c := testBalancer()
	b.Observe("cur", PathStats{SRTT: ms(200)})
	b.Observe("other", PathStats{SRTT: ms(300)})
	b.Pick("de", []string{"cur", "other"})
	c.add(switchCooldown + time.Minute)

	nodes := []string{"cur", "other"}
	b.Observe("cur", PathStats{SRTT: ms(200)})
	b.Observe("other", PathStats{SRTT: ms(50)})
	b.Pick("de", nodes) // окно 1 за кандидата
	c.add(pollStats)
	b.Observe("cur", PathStats{SRTT: ms(200)})
	b.Observe("other", PathStats{SRTT: ms(400)}) // сорвался
	b.Pick("de", nodes)
	c.add(pollStats)
	b.Observe("cur", PathStats{SRTT: ms(200)})
	b.Observe("other", PathStats{SRTT: ms(50)}) // снова хорош

	// Счёт обнулился: одного окна снова мало.
	if got := b.Pick("de", nodes); got != "cur" {
		t.Fatalf("зачёл прерванное преимущество: %q", got)
	}
}

// Выбывший узел заменяется немедленно: ждать «устойчивости» некогда, текущего
// выхода больше нет.
func TestChosenNodeGoneSwitchesAtOnce(t *testing.T) {
	b, _ := testBalancer()
	b.Observe("a", PathStats{SRTT: ms(20)})
	b.Observe("b", PathStats{SRTT: ms(500)})
	if got := b.Pick("de", []string{"a", "b"}); got != "a" {
		t.Fatalf("первый выбор: %q", got)
	}
	if got := b.Pick("de", []string{"b"}); got != "b" {
		t.Fatalf("выбывший узел не заменён: %q", got)
	}
}

// Замолчавший выбранный узел не должен держать трафик вечно.
//
// Метрика снимается с живого соединения, поэтому её пропажа означает, что связь
// оборвалась или замерла. Если требовать для переключения свежий замер ОБОИХ,
// сравнивать станет не с чем — и балансировщик прилипнет к мёртвому узлу
// навсегда.
func TestLeavesSilentNode(t *testing.T) {
	b, c := testBalancer()
	b.Observe("cur", PathStats{SRTT: ms(20)})
	b.Observe("other", PathStats{SRTT: ms(300)})
	if got := b.Pick("de", []string{"cur", "other"}); got != "cur" {
		t.Fatalf("первый выбор: %q", got)
	}
	c.add(switchCooldown + time.Minute)

	// cur замолчал (метрику больше не обновляем), other продолжает отвечать —
	// пусть и медленнее, чем cur когда-то.
	keep := map[string]PathStats{"other": {SRTT: ms(300)}}
	c.add(statsStale + time.Minute)
	if got := win(b, c, "de", []string{"cur", "other"}, keep); got != "other" {
		t.Fatalf("остался на замолчавшем узле: %q", got)
	}
}

// Но уходить в неизвестность нельзя: если о кандидате свежих данных нет,
// переключение — лотерея, а не выбор.
func TestDoesNotSwitchToUnmeasured(t *testing.T) {
	b, c := testBalancer()
	b.Observe("cur", PathStats{SRTT: ms(300)})
	b.Pick("de", []string{"cur"})
	c.add(switchCooldown + time.Minute)

	keep := map[string]PathStats{"cur": {SRTT: ms(300)}}
	if got := win(b, c, "de", []string{"cur", "silent"}, keep); got != "cur" {
		t.Fatalf("ушёл на неизмеренный узел: %q", got)
	}
}

// Узел без метрик не должен вытеснять измеренный: о нём ничего не известно.
func TestUnmeasuredNodeLosesToMeasured(t *testing.T) {
	b, _ := testBalancer()
	b.Observe("known", PathStats{SRTT: ms(300)})

	if got := b.Pick("de", []string{"known", "unknown"}); got != "known" {
		t.Fatalf("выбран неизмеренный %q", got)
	}
}

// Но если измеренных нет вовсе — берём хоть какой-то: пустой ответ означал бы
// «выпускай здесь», а узел под тегом есть.
func TestFallsBackToUnmeasured(t *testing.T) {
	b, _ := testBalancer()
	if got := b.Pick("de", []string{"unknown"}); got != "unknown" {
		t.Fatalf("не выбран единственный кандидат: %q", got)
	}
}

// Протухшая метрика в расчёт не идёт: узел мог лечь час назад.
func TestStaleStatsIgnored(t *testing.T) {
	b, c := testBalancer()
	b.Observe("stale", PathStats{SRTT: ms(1)})
	c.add(statsStale + time.Minute)
	b.Observe("fresh", PathStats{SRTT: ms(100)})

	if got := b.Pick("de", []string{"stale", "fresh"}); got != "fresh" {
		t.Fatalf("выбран узел с протухшей метрикой: %q", got)
	}
}

// Нет кандидатов — нет выбора. Флоу выйдет на текущем узле, а не умрёт.
func TestNoCandidatesNoPick(t *testing.T) {
	b, _ := testBalancer()
	if got := b.Pick("de", nil); got != "" {
		t.Fatalf("выбран %q при пустом списке", got)
	}
}

// Порядок кандидатов не влияет на выбор: иначе равные узлы менялись бы местами
// от вызова к вызову — тот же флаппинг, только незаметный.
func TestOrderDoesNotAffectChoice(t *testing.T) {
	b, _ := testBalancer()
	first := b.Pick("de", []string{"a", "b", "c"})

	b2, _ := testBalancer()
	second := b2.Pick("de", []string{"c", "b", "a"})

	if first != second {
		t.Fatalf("порядок повлиял: %q против %q", first, second)
	}
}
