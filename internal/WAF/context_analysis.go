package waf

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ContextMiddleware implements stateful analysis of user interactions.
// Detects anomalous behavior such as BOLA (Broken Object Level Authorization)
// by tracking unique resource IDs accessed within a time window.
type ContextMiddleware struct {
	waf       *WAF
	window    time.Duration
	threshold int
	banDuration time.Duration
	logDetections bool
}

// NewContextMiddleware creates a context analyzer with default settings.
// window: time period for counting unique resource IDs.
// threshold: maximum allowed unique resources in window before ban.
func NewContextMiddleware(w *WAF) *ContextMiddleware {
	return &ContextMiddleware{
		waf:           w,
		window:        60 * time.Second,
		threshold:     20,
		banDuration:   5 * time.Minute,
		logDetections: true,
	}
}

// NewContextMiddlewareWithConfig creates a context analyzer with custom settings.
func NewContextMiddlewareWithConfig(w *WAF, window time.Duration, threshold int, banDuration time.Duration) *ContextMiddleware {
	return &ContextMiddleware{
		waf:           w,
		window:        window,
		threshold:     threshold,
		banDuration:   banDuration,
		logDetections: true,
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
			// Potential BOLA/resource enumeration attack detected
			m.waf.bans.Ban(id, m.banDuration)
			if m.logDetections {
				log.Printf("BOLA-like behavior detected from %s: %d unique resources in %s window", id, uniqueCount, m.window)
			}
			w.Header().Set("Retry-After", "300")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Session tracking for future correlation analysis
		_ = session // placeholder for extended session-level analytics

		next.ServeHTTP(w, r)
	})
}
