package mobile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"quicdiver/internal/client/config"
)

func TestImportBundle(t *testing.T) {
	b := config.Bundle{
		V: 1,
		T: "test_token_123",
		E: []config.BundleEntry{
			{A: "192.0.2.1:443", S: "node.example.com"},
		},
	}
	bundleStr := b.String()

	cfgJSON, err := ImportBundle(bundleStr)
	if err != nil {
		t.Fatalf("ImportBundle error: %v", err)
	}
	if !strings.Contains(cfgJSON, "test_token_123") {
		t.Errorf("expected token in imported config, got: %s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, "192.0.2.1:443") {
		t.Errorf("expected node address in imported config, got: %s", cfgJSON)
	}

	_, err = ImportBundle("invalid_bundle_string")
	if err == nil {
		t.Error("expected error for invalid bundle string, got nil")
	}
}

func TestFDSource(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer w.Close()

	src, err := NewFDSource(int(r.Fd()), 1500)
	if err != nil {
		t.Fatalf("NewFDSource failed: %v", err)
	}
	defer src.Close()

	testPacket := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02}
	_, err = w.Write(testPacket)
	if err != nil {
		t.Fatalf("write to pipe failed: %v", err)
	}

	pkts, err := src.Recv(t.Context())
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if len(pkts[0].Data) != len(testPacket) {
		t.Errorf("packet length mismatch: got %d, want %d", len(pkts[0].Data), len(testPacket))
	}
}

func TestStartStopEngine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer w.Close()

	// Initial status should be stopped
	statusStr := GetStatus()
	var st StatusInfo
	if err := json.Unmarshal([]byte(statusStr), &st); err != nil {
		t.Fatalf("unmarshal status error: %v", err)
	}
	if st.State != "stopped" {
		t.Errorf("expected state stopped, got %s", st.State)
	}

	// Start engine with empty config (local netstack mode)
	err = StartEngine(int(r.Fd()), "")
	if err != nil {
		t.Fatalf("StartEngine error: %v", err)
	}

	// Wait briefly for engine worker to start
	time.Sleep(50 * time.Millisecond)

	statusStr = GetStatus()
	if err := json.Unmarshal([]byte(statusStr), &st); err != nil {
		t.Fatalf("unmarshal status error: %v", err)
	}
	if st.State != "connected" && st.State != "connecting" {
		t.Errorf("expected connecting or connected state, got %s", st.State)
	}

	// Update rules while running
	err = UpdateRules("dom:example.com=chain\ncidr:10.0.0.0/8=direct")
	if err != nil {
		t.Fatalf("UpdateRules error: %v", err)
	}

	statusStr = GetStatus()
	if err := json.Unmarshal([]byte(statusStr), &st); err != nil {
		t.Fatalf("unmarshal status error: %v", err)
	}
	if st.ActiveRules != 2 {
		t.Errorf("expected 2 active rules, got %d", st.ActiveRules)
	}

	// Stop engine
	err = StopEngine()
	if err != nil {
		t.Fatalf("StopEngine error: %v", err)
	}

	statusStr = GetStatus()
	if err := json.Unmarshal([]byte(statusStr), &st); err != nil {
		t.Fatalf("unmarshal status error: %v", err)
	}
	if st.State != "stopped" {
		t.Errorf("expected state stopped after StopEngine, got %s", st.State)
	}
}

func TestUpdateRulesWhenNotRunning(t *testing.T) {
	_ = StopEngine()
	err := UpdateRules("dom:test.com=chain")
	if err == nil {
		t.Error("expected error updating rules when engine is stopped, got nil")
	}
}

func TestNetstackTunnelPair(t *testing.T) {
	clientEp, serverEp := newNetstackTunnelPair()
	defer clientEp.Close()
	defer serverEp.Close()

	data := []byte("hello netstack")
	_, err := clientEp.WritePacket(data)
	if err != nil {
		t.Fatalf("clientEp WritePacket error: %v", err)
	}

	buf := make([]byte, 100)
	n, err := serverEp.ReadPacket(buf)
	if err != nil {
		t.Fatalf("serverEp ReadPacket error: %v", err)
	}
	if string(buf[:n]) != string(data) {
		t.Errorf("read mismatch: got %q, want %q", buf[:n], data)
	}
}
