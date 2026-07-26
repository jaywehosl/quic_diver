package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

func TestClientConfigBackupEndpoints(t *testing.T) {
	dir := t.TempDir()
	store, err := db.Open(dir + "/node.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	adminToken, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	hash := auth.Hash(adminToken)
	if err := store.PutToken(ctx, hash, auth.RoleAdmin, "admin"); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Store: store}
	handler := serveClientConfigBackup(cfg, http.NotFoundHandler())

	// 1. GET — бэкапа пока нет
	req := httptest.NewRequest(http.MethodGet, "/qd-backup", nil)
	req.Header.Set(auth.HeaderToken, adminToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status %d, want 200", rec.Code)
	}
	var resp BackupConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Exists {
		t.Fatal("бэкап не должен существовать")
	}

	// 2. POST — сохраняем бэкап
	payload := `{"routing":{"rules":["geosite:google=node1"]}}`
	reqPost := httptest.NewRequest(http.MethodPost, "/qd-backup", bytes.NewBufferString(payload))
	reqPost.Header.Set(auth.HeaderToken, adminToken)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusOK {
		t.Fatalf("POST status %d, want 200", recPost.Code)
	}

	// 3. GET — теперь бэкап существует и возвращает payload
	req2 := httptest.NewRequest(http.MethodGet, "/qd-backup", nil)
	req2.Header.Set(auth.HeaderToken, adminToken)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("GET status %d, want 200", rec2.Code)
	}
	var resp2 BackupConfigResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	if !resp2.Exists {
		t.Fatal("бэкап должен существовать")
	}
	if resp2.ConfigJSON != payload {
		t.Fatalf("получено %q, ожидалось %q", resp2.ConfigJSON, payload)
	}
}
