package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"sigil-proxy/internal/sigilsock"
)

var sigilEmitter = sigilsock.NewEmitter("", "sigil-proxy")

type DemoRequest struct {
	Session string `json:"session,omitempty"`
	Prompt  string `json:"prompt"`
}

type DemoResponse struct {
	Timestamp     string  `json:"timestamp"`
	SanitizedPrompt string  `json:"sanitized_prompt"`
	RiskScore     float64 `json:"risk_score"`
	Action        string  `json:"action"`
	Reason        string  `json:"reason"`
	LatencyMs     int64   `json:"latency_ms"`
}

// Compiled regex patterns for automatic secret stripping
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{20,}`),             // Anthropic Claude keys
	regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`),                     // OpenAI keys
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),                     // GitHub Personal Access Tokens
	regexp.MustCompile(`-----BEGIN (?:RSA|PRIVATE) KEY-----[^-]*-----END (?:RSA|PRIVATE) KEY-----`), // PEM Private Keys
}

func sanitizePayload(input string) string {
	cleaned := input
	for _, re := range secretPatterns {
		cleaned = re.ReplaceAllString(cleaned, "[REDACTED-SECRET]")
	}
	return cleaned
}

func handleDemoScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read body"}`, http.StatusBadRequest)
		return
	}

	var req DemoRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid payload: %v"}`, err), http.StatusBadRequest)
		return
	}

	if req.Prompt == "" {
		req.Prompt = "Empty prompt received"
	}

	// 1. Sanitize first: strip out any injected secrets or API keys
	safePrompt := sanitizePayload(req.Prompt)

	// 2. Threat detection on the sanitized stream
	lower := strings.ToLower(safePrompt)
	riskScore := 0.00
	action := "FORWARD"
	reason := "Clean request. No threat vectors detected."

	session := strings.TrimSpace(req.Session)
	if session == "" {
		session = strings.TrimSpace(r.Header.Get("X-Sentinel-Session"))
	}
	if session == "" {
		session = strings.TrimSpace(r.Header.Get("X-Sigil-Session"))
	}
	if session == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
			session = host
		} else {
			session = "default"
		}
	}

	if strings.Contains(lower, "ignore previous instructions") ||
		strings.Contains(lower, "system prompt") ||
		strings.Contains(lower, "bypass") ||
		strings.Contains(lower, "jailbreak") {
		riskScore = 0.98
		action = "BLOCK"
		reason = "Prompt injection vector identified at network edge."
		sigilEmitter.EmitThreatSignal(session, r.URL.Path, []string{"INJECTION"}, "sigil-proxy-injection", riskScore, 300, reason)
	} else if safePrompt != req.Prompt {
		riskScore = 0.85
		action = "SANITIZED"
		reason = "Credential leak attempt intercepted. Sensitive tokens scrubbed at perimeter."
		sigilEmitter.EmitThreatSignal(session, r.URL.Path, []string{"SECRET"}, "sigil-proxy-secret", riskScore, 300, reason)
	}

	resp := DemoResponse{
		Timestamp:       time.Now().Format("2006-01-02 15:04:05"),
		SanitizedPrompt: safePrompt,
		RiskScore:       riskScore,
		Action:          action,
		Reason:          reason,
		LatencyMs:       TimeSince(start),
	}

	json.NewEncoder(w).Encode(resp)
}

func TimeSince(t time.Time) int64 {
	return time.Since(t).Milliseconds()
}

func main() {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "11435"
	}
	http.HandleFunc("/api/demo", handleDemoScan)
	fmt.Printf("SiGiL Proxy Core active on port %s with automated secret stripping (sigil.sock=%s)...\n", port, sigilEmitter.SockPath)
	http.ListenAndServe(":"+port, nil)
}
