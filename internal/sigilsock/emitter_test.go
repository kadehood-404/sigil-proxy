package sigilsock

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
)

func TestEmitterFailOpenAndUnixSend(t *testing.T) {
	// Fail open when socket does not exist.
	missing := NewEmitter(filepath.Join(t.TempDir(), "missing.sock"), "sigil-proxy")
	if missing.EmitThreatSignal("s1", "/api/demo", []string{"INJECTION"}, "", 0.98, 300, "") {
		t.Fatal("expected false when socket is absent")
	}

	// Real Unix socket round-trip.
	sockPath := filepath.Join(t.TempDir(), "sigil.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		gotCh <- line
	}()

	em := NewEmitter(sockPath, "sigil-proxy")
	if !em.EmitThreatSignal("agent-9", "/api/demo", []string{"INJECTION"}, "sigil-proxy-injection", 0.98, 300, "blocked") {
		t.Fatal("expected EmitThreatSignal to succeed")
	}

	raw := <-gotCh
	var env struct {
		V       int                 `json:"v"`
		Source  string              `json:"source"`
		Type    string              `json:"type"`
		Payload ThreatSignalPayload `json:"payload"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("bad JSON: %v (%q)", err, raw)
	}
	if env.V != 1 || env.Source != "sigil-proxy" || env.Type != "threat_signal" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	if env.Payload.Session != "agent-9" || env.Payload.RecommendedLock != "locked" || env.Payload.Category != "prompt_injection" {
		t.Fatalf("unexpected payload: %+v", env.Payload)
	}
}
