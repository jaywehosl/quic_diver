package routing

import "testing"

// Метка переживает круг «сериализовать → передать → разобрать»: она едет между
// узлами, и искажение увело бы флоу не туда.
func TestRouteRoundTrip(t *testing.T) {
	for _, want := range []Route{Direct, Node("n4"), Auto("de")} {
		got, err := Parse(want.String())
		if err != nil {
			t.Fatalf("%v → %q: %v", want, want.String(), err)
		}
		if got != want {
			t.Fatalf("%q разобралось как %+v, ожидалось %+v", want.String(), got, want)
		}
	}
}

// Пустая метка — не ошибка: так выглядит клиент без правил и старый клиент,
// который про метки не знает. Оба должны обслуживаться.
func TestEmptyLabelMeansDirect(t *testing.T) {
	for _, s := range []string{"", "   ", "direct"} {
		r, err := Parse(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if !r.IsDirect() {
			t.Fatalf("%q дало %+v, ожидался выход здесь", s, r)
		}
	}
}

// Неизвестный префикс не должен молча сойти за имя узла — иначе флоу уедет не
// туда и это будет незаметно.
func TestUnknownPrefixRejected(t *testing.T) {
	for _, s := range []string{"chain:foo", "geo:de", "auto:"} {
		if _, err := Parse(s); err == nil {
			t.Fatalf("метка %q принята", s)
		}
	}
}

// Узел, названный в метке, выпускает наружу сам, а не пересылает себе же.
func TestSelfIsExit(t *testing.T) {
	d, next := Node("n4").Decide("n4", nil)
	if d != Exit || next != "" {
		t.Fatalf("решение %v→%q, ожидался выход здесь", d, next)
	}
}

// Чужой узел — транзит, и метка ведёт именно к нему.
func TestOtherNodeIsTransit(t *testing.T) {
	d, next := Node("n4").Decide("n1", nil)
	if d != Transit || next != "n4" {
		t.Fatalf("решение %v→%q, ожидался транзит на n4", d, next)
	}
}

// Категория: выбор делает узел, а не клиент. Если выбранный — он сам, выпускает.
func TestAutoPicksNode(t *testing.T) {
	pick := func(tag string) string {
		if tag != "de" {
			t.Fatalf("категория %q", tag)
		}
		return "n7"
	}
	d, next := Auto("de").Decide("n1", pick)
	if d != Transit || next != "n7" {
		t.Fatalf("решение %v→%q, ожидался транзит на n7", d, next)
	}

	d, next = Auto("de").Decide("n7", pick)
	if d != Exit || next != "" {
		t.Fatalf("выбранный узел — он сам: %v→%q, ожидался выход", d, next)
	}
}

// Категория без живых узлов — выпускаем здесь, а не глушим флоу: остаться без
// связи хуже, чем выйти не из той страны.
func TestAutoWithoutCandidatesFallsBackToExit(t *testing.T) {
	d, next := Auto("de").Decide("n1", func(string) string { return "" })
	if d != Exit || next != "" {
		t.Fatalf("решение %v→%q, ожидался выход здесь", d, next)
	}
	// И то же, если выбирать некому вовсе.
	if d, _ := Auto("de").Decide("n1", nil); d != Exit {
		t.Fatalf("без выбирающего решение %v, ожидался выход здесь", d)
	}
}
