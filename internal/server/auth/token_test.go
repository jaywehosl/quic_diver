package auth

import (
	"strings"
	"testing"
)

func TestGenerateUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, prefix) {
			t.Fatalf("нет префикса: %q", tok)
		}
		if seen[tok] {
			t.Fatal("повтор токена — генератор предсказуем")
		}
		seen[tok] = true
	}
}

func TestHashStable(t *testing.T) {
	tok, _ := Generate()
	if Hash(tok) != Hash(tok) {
		t.Fatal("хеш нестабилен")
	}
	other, _ := Generate()
	if Hash(tok) == Hash(other) {
		t.Fatal("разные токены дали один хеш")
	}
}

// Хеш не должен содержать самого токена: даже частичной утечки нет.
func TestHashHidesToken(t *testing.T) {
	tok, _ := Generate()
	h := Hash(tok)
	if strings.Contains(h, strings.TrimPrefix(tok, prefix)) {
		t.Fatal("хеш содержит токен")
	}
}

func TestLooksLikeToken(t *testing.T) {
	tok, _ := Generate()
	if !LooksLikeToken(tok) {
		t.Fatal("свой токен не распознан")
	}
	for _, bad := range []string{"", "qd_", "hello", "Bearer xyz"} {
		if LooksLikeToken(bad) {
			t.Fatalf("мусор принят за токен: %q", bad)
		}
	}
}

func TestEqualHashConstantTime(t *testing.T) {
	tok, _ := Generate()
	h := Hash(tok)
	if !EqualHash(h, h) {
		t.Fatal("равные хеши не совпали")
	}
	if EqualHash(h, Hash("другое")) {
		t.Fatal("разные хеши совпали")
	}
	// разная длина не должна паниковать
	if EqualHash(h, "short") {
		t.Fatal("хеши разной длины совпали")
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleUser, RoleAdmin, RoleNode} {
		if !r.Valid() {
			t.Fatalf("роль %q не валидна", r)
		}
	}
	if Role("root").Valid() {
		t.Fatal("выдуманная роль валидна")
	}
}
