package android

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"quicdiver/internal/client/config"
	"quicdiver/internal/mobile"
)

func TestAndroidWrapper(t *testing.T) {
	b := config.Bundle{
		V: 1,
		T: "token_wrapper_test",
		E: []config.BundleEntry{
			{A: "192.0.2.100:443", S: "node.example.com"},
		},
	}
	bundleStr := b.String()

	cfgJSON, err := ImportBundle(bundleStr)
	if err != nil {
		t.Fatalf("ImportBundle error: %v", err)
	}
	if !strings.Contains(cfgJSON, "token_wrapper_test") {
		t.Errorf("expected token in config, got: %s", cfgJSON)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer w.Close()

	if err := StartEngine(int(r.Fd()), ""); err != nil {
		t.Fatalf("StartEngine error: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	statusStr := GetStatus()
	var st mobile.StatusInfo
	if err := json.Unmarshal([]byte(statusStr), &st); err != nil {
		t.Fatalf("GetStatus unmarshal error: %v", err)
	}
	if st.State != "connected" && st.State != "connecting" {
		t.Errorf("unexpected state: %s", st.State)
	}

	if err := UpdateRules("dom:test.org=chain"); err != nil {
		t.Fatalf("UpdateRules error: %v", err)
	}

	if err := StopEngine(); err != nil {
		t.Fatalf("StopEngine error: %v", err)
	}
}
