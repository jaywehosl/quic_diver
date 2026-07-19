package server

import (
	"context"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// authorizeToken — прошёл ли токен авторизацию узла.
func authorizeToken(t *testing.T, cfg Config, token string) bool {
	t.Helper()
	sess := &auth.Session{}
	return authorize(context.Background(), cfg, sess, token)
}

// Исчерпавший лимит клиент внутрь не проходит — иначе тариф не имел бы смысла.
func TestQuotaBlocksClient(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutToken(ctx, hash, auth.RoleUser, "клиент")
	store.SetTrafficLimit(ctx, hash, 1000, 0)

	if !authorizeToken(t, cfg, token) {
		t.Fatal("клиент в пределах лимита не пущен")
	}
	store.ReportNodeTraffic(ctx, "bitter", []db.NodeTraffic{{TokenHash: hash, BytesIn: 1000}})
	if authorizeToken(t, cfg, token) {
		t.Fatal("клиент с израсходованным лимитом пущен")
	}
}

// Админа и узел лимитом не глушим: потерять управление сетью из-за
// израсходованного тарифа нельзя.
func TestQuotaDoesNotBlockAdminOrNode(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()

	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleNode} {
		token, _ := auth.Generate()
		hash := auth.Hash(token)
		store.PutToken(ctx, hash, role, string(role))
		store.SetTrafficLimit(ctx, hash, 100, 0)
		store.ReportNodeTraffic(ctx, "bitter", []db.NodeTraffic{{TokenHash: hash, BytesIn: 99999}})

		if !authorizeToken(t, cfg, token) {
			t.Fatalf("роль %q заблокирована лимитом трафика", role)
		}
	}
}

// Новый период открывает доступ заново, без вмешательства администратора.
func TestQuotaReopensAfterReset(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutToken(ctx, hash, auth.RoleUser, "клиент")
	store.SetTrafficLimit(ctx, hash, 1000, 30)
	store.ReportNodeTraffic(ctx, "bitter", []db.NodeTraffic{{TokenHash: hash, BytesIn: 5000}})
	store.QuotaOf(ctx, hash) // завести период

	store.ReportNodeTraffic(ctx, "bitter", []db.NodeTraffic{{TokenHash: hash, BytesIn: 6500}})
	if authorizeToken(t, cfg, token) {
		t.Fatal("клиент за пределом лимита пущен")
	}
	if err := store.ResetTraffic(ctx, hash); err != nil {
		t.Fatal(err)
	}
	if !authorizeToken(t, cfg, token) {
		t.Fatal("после сброса периода клиент не пущен")
	}
}

// Клиент без лимита не должен страдать от проверки вовсе.
func TestUnlimitedClientPasses(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutToken(ctx, hash, auth.RoleUser, "безлимит")
	store.ReportNodeTraffic(ctx, "bitter", []db.NodeTraffic{{TokenHash: hash, BytesIn: 1 << 40}})

	if !authorizeToken(t, cfg, token) {
		t.Fatal("клиент без лимита не пущен")
	}
}
