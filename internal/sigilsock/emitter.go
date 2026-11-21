// Package sigilsock implements a zero-dependency SiGiL IPC v1 client for
// emitting threat_signal envelopes from sigil-proxy to sentinel-x over
// sigil.sock (AF_UNIX SOCK_STREAM NDJSON).
package sigilsock

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ProtocolVersion = 1

// DefaultSockPath resolves SIGIL_SOCK -> $XDG_RUNTIME_DIR/sigil.sock -> /tmp/sigil-<uid>.sock.
func DefaultSockPath() string {
	if env := strings.TrimSpace(os.Getenv("SIGIL_SOCK")); env != "" {
		return env
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); xdg != "" {
		return filepath.Join(xdg, "sigil.sock")
	}
	return fmt.Sprintf("/tmp/sigil-%d.sock", os.Getuid())
}

// SeverityAndLock maps matched detector types to (severity, category, recommended_lock).
func SeverityAndLock(matchedTypes []string) (severity, category, recommendedLock string) {
	upper := make(map[string]bool, len(matchedTypes))
	for _, m := range matchedTypes {
		upper[strings.ToUpper(strings.TrimSpace(m))] = true
	}
	for _, k := range []string{"INJECTION", "PROMPT_INJECTION", "JAILBREAK"} {
		if upper[k] {
			return "high", "prompt_injection", "locked"
		}
	}
	for _, k := range []string{"SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY"} {
		if upper[k] {
			return "high", "secret_leak", "elevated"
		}
	}
	for _, k := range []string{"PII", "SSN", "EMAIL", "PHONE"} {
		if upper[k] {
			return "medium", "pii_leak", "elevated"
		}
	}
	return "medium", "anomalous_prompt", "elevated"
}

// Envelope is a SiGiL IPC v1 NDJSON frame.
type Envelope struct {
	V       int       `json:"v"`
	ID      string    `json:"id"`
	TS      time.Time `json:"ts"`
	Source  string    `json:"source"`
	Type    string    `json:"type"`
	Payload any       `json:"payload"`
}

// ThreatSignalPayload matches sentinel-x's sigil.ThreatSignalPayload schema.
type ThreatSignalPayload struct {
	Session         string   `json:"session"`
	Severity        string   `json:"severity"`
	Category        string   `json:"category"`
	RuleID          string   `json:"rule_id"`
	Confidence      float64  `json:"confidence"`
	RecommendedLock string   `json:"recommended_lock"`
	TTLSeconds      int      `json:"ttl_seconds"`
	MatchedTypes    []string `json:"matched_types"`
	Note            string   `json:"note"`
}

// Emitter is a fail-open, best-effort NDJSON emitter over AF_UNIX SOCK_STREAM.
type Emitter struct {
	SockPath string
	Source   string
	Timeout  time.Duration
}

// NewEmitter returns an Emitter configured with defaults matching SigilSockEmitter.
func NewEmitter(sockPath, source string) *Emitter {
	if strings.TrimSpace(sockPath) == "" {
		sockPath = DefaultSockPath()
	}
	if strings.TrimSpace(source) == "" {
		source = "sigil-proxy"
	}
	return &Emitter{
		SockPath: sockPath,
		Source:   source,
		Timeout:  500 * time.Millisecond,
	}
}

// SendEnvelope writes one v1 NDJSON envelope to sigil.sock. Fails open
// (returns false) if sentinel-x is not running.
func (e *Emitter) SendEnvelope(msgType string, payload any) bool {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	env := Envelope{
		V:       ProtocolVersion,
		ID:      newUUID(),
		TS:      time.Now().UTC().Truncate(time.Second),
		Source:  e.Source,
		Type:    msgType,
		Payload: payload,
	}
	wire, err := json.Marshal(env)
	if err != nil {
		return false
	}
	wire = append(wire, '\n')

	conn, err := net.DialTimeout("unix", e.SockPath, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(wire)
	return err == nil
}

// EmitThreatSignal builds and sends a v1 threat_signal to sentinel-x.
func (e *Emitter) EmitThreatSignal(session, path string, matchedTypes []string, ruleID string, confidence float64, ttlSeconds int, note string) bool {
	clean := make([]string, 0, len(matchedTypes))
	for _, t := range matchedTypes {
		if s := strings.TrimSpace(t); s != "" {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return false
	}
	if strings.TrimSpace(session) == "" {
		session = "default"
	}
	if strings.TrimSpace(ruleID) == "" {
		ruleID = "sigil-proxy-match"
	}
	if confidence <= 0 {
		confidence = 0.90
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	sev, cat, lock := SeverityAndLock(clean)
	if strings.TrimSpace(note) == "" {
		note = fmt.Sprintf("Matched %s on %s", strings.Join(clean, ","), path)
	}
	return e.SendEnvelope("threat_signal", ThreatSignalPayload{
		Session:         session,
		Severity:        sev,
		Category:        cat,
		RuleID:          ruleID,
		Confidence:      confidence,
		RecommendedLock: lock,
		TTLSeconds:      ttlSeconds,
		MatchedTypes:    clean,
		Note:            note,
	})
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
