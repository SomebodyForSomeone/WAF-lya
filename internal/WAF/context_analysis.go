package waf

import (
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ContextMiddleware implements stateful analysis of user interactions.
// Detects anomalous behavior such as BOLA (Broken Object Level Authorization)
// by tracking unique resource IDs accessed within a time window.
// Repeated violations increase ban duration exponentially (dynamic throttling).
type ContextMiddleware struct {
	waf               *WAF
	window            time.Duration
	threshold         int
	banDuration       time.Duration
	multiplier        float64
	violationResetTTL time.Duration
	logDetections     bool
}

// NewContextMiddleware creates a context analyzer with default settings.
// window: time period for counting unique resource IDs.
// threshold: maximum allowed unique resources in window before ban.
func NewContextMiddleware(w *WAF) *ContextMiddleware {
	return &ContextMiddleware{
		waf:               w,
		window:            60 * time.Second,
		threshold:         20,
		banDuration:       5 * time.Minute,
		multiplier:        2.0,
		violationResetTTL: 24 * time.Hour,
		logDetections:     true,
	}
}

// NewContextMiddlewareWithConfig creates a context analyzer with custom settings.
func NewContextMiddlewareWithConfig(w *WAF, window time.Duration, threshold int, banDuration time.Duration) *ContextMiddleware {
	return &ContextMiddleware{
		waf:               w,
		window:            window,
		threshold:         threshold,
		banDuration:       banDuration,
		multiplier:        2.0,
		violationResetTTL: 24 * time.Hour,
		logDetections:     true,
	}
}

func (m *ContextMiddleware) push(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.waf == nil {
			next.ServeHTTP(w, r)
			return
		}

		id := extractIP(r.RemoteAddr)

		// Quick check for already banned identifier
		if m.waf.bans.IsBanned(id) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		st := m.waf.states.Get(id)
		if st == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Extract session ID from header or cookie
		session := r.Header.Get("X-Session-ID")
		if session == "" {
			if c, err := r.Cookie("sessionid"); err == nil {
				session = c.Value
			}
		}

		// Extract ResourceID from query param 'id' or numeric path segment
		resource := r.URL.Query().Get("id")
		if resource == "" {
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				// Check if last path segment is numeric (likely a resource ID)
				if _, err := strconv.Atoi(last); err == nil {
					resource = last
				}
			}
		}

		// Update state: maintain map of accessed resources with timestamps
		st.mu.Lock()
		now := time.Now()

		// Initialize or retrieve resources map from Meta
		var resources map[string]time.Time
		if v, ok := st.Meta["resources"]; ok {
			resources = v.(map[string]time.Time)
		} else {
			resources = make(map[string]time.Time)
		}

		// Record resource access
		if resource != "" {
			resources[resource] = now
		}

		// Clean up old entries outside the time window
		for k, t := range resources {
			if now.Sub(t) > m.window {
				delete(resources, k)
			}
		}

		st.Meta["resources"] = resources
		st.LastSeen = now
		st.mu.Unlock()

		// Anomaly analysis: trigger alert if unique resources exceed threshold
		uniqueCount := len(resources)
		if uniqueCount > m.threshold {
			// Potential BOLA/resource enumeration attack detected.
			// Apply dynamic throttling: increase ban duration on repeated violations.
			st.mu.Lock()
			now := time.Now()

			// Check if violation counter should be reset (too much time passed since last BOLA violation)
			var bolaViolations int
			var lastBolaViolationTime time.Time
			if v, ok := st.Meta["bola_violations"]; ok {
				bolaViolations = v.(int)
			}
			if v, ok := st.Meta["last_bola_violation_time"]; ok {
				lastBolaViolationTime = v.(time.Time)
			}

			if !lastBolaViolationTime.IsZero() && now.Sub(lastBolaViolationTime) > m.violationResetTTL {
				bolaViolations = 0
			}

			// Increment violation counter
			bolaViolations++
			st.Meta["bola_violations"] = bolaViolations
			st.Meta["last_bola_violation_time"] = now

			// Calculate ban duration: base * (multiplier ^ violations)
			banDuration := time.Duration(float64(m.banDuration) * math.Pow(m.multiplier, float64(bolaViolations-1)))
			violationCount := bolaViolations
			st.mu.Unlock()

			m.waf.bans.Ban(id, banDuration)
			if m.logDetections {
				log.Printf("[%s] BOLA-like behavior detected from %s: %d unique resources in %s window, banned for %s (violation #%d)", now.Format(time.RFC3339), id, uniqueCount, m.window, banDuration, violationCount)
			}
			w.Header().Set("Retry-After", strconv.FormatInt(int64(banDuration.Seconds()), 10))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Reset BOLA violation counter on successful request
		st.mu.Lock()
		st.Meta["bola_violations"] = 0
		st.Meta["last_bola_violation_time"] = time.Time{}
		st.mu.Unlock()

		// Session tracking for future correlation analysis
		_ = session // placeholder for extended session-level analytics

		next.ServeHTTP(w, r)
	})
}
