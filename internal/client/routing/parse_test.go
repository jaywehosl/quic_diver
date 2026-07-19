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
