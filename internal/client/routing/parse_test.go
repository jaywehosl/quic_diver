package routing

import "testing"

// Правила пишут и в строку через ';' (флаг), и по одному на строку (панель,
// файл). Требовать один вариант значило бы ловить пользователя на пустом месте.
func TestParseAcceptsBothSeparators(t *testing.T) {
	byLine, err := ParseRules("dom:a.example=direct\ncidr:10.0.0.0/8=chain")
	if err != nil {
		t.Fatal(err)
	}
	bySemicolon, err := ParseRules("dom:a.example=direct;cidr:10.0.0.0/8=chain")
	if err != nil {
		t.Fatal(err)
	}
	if len(byLine) != 2 || len(bySemicolon) != 2 {
		t.Fatalf("построчно %d, через ';' %d", len(byLine), len(bySemicolon))
	}
	if byLine[0].Out != "direct" || byLine[1].Out != "chain" {
		t.Fatalf("выходы склеились: %+v", byLine)
	}
}

// Закомментированное правило пропускается: файл правится руками, и без пометок
// правило пришлось бы удалять, чтобы временно отключить.
func TestParseSkipsComments(t *testing.T) {
	rules, err := ParseRules("# выключено на время\n#dom:a.example=direct\ndom:b.example=chain")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Match.Domain != "b.example" {
		t.Fatalf("комментарии не пропущены: %+v", rules)
	}
}

// Пробелы вокруг разделителей не должны ломать правило: «dom:youtube.com =
// auto:de» читается лучше слитного, и панель со справкой показывают именно так.
func TestParseTolerantToSpaces(t *testing.T) {
	rules, err := ParseRules("  dom:youtube.com = auto:de  \n cidr:192.168.0.0/16 = direct \nport: 22 =direct")
	if err != nil {
		t.Fatalf("пробелы сломали разбор: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("правил %d: %+v", len(rules), rules)
	}
	if rules[0].Match.Domain != "youtube.com" || rules[0].Out != "auto:de" {
		t.Fatalf("домен: %+v", rules[0])
	}
	if !rules[1].Match.CIDR.IsValid() || rules[1].Out != "direct" {
		t.Fatalf("подсеть: %+v", rules[1])
	}
	if rules[2].Match.Port != 22 {
		t.Fatalf("порт: %+v", rules[2])
	}
}
