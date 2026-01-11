package waf

import (
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitMiddleware implements a token-bucket rate limiter per identifier
// (IP/session). On exceed it adds the identifier to the banlist.
// Repeated violations increase ban duration exponentially (dynamic throttling).
type RateLimitMiddleware struct{
	waf               *WAF
	limit             rate.Limit
	burst             int
	banDuration       time.Duration
	multiplier        float64       // ban duration multiplier on repeat offenses (default 2.0)
	violationResetTTL time.Duration // reset violation counter after this duration (default 24h)
}

// NewRateLimitMiddleware creates a rate limiter middleware.
// `limit` is requests per second, `burst` is bucket capacity, `ban` is ban duration on exceed.
func NewRateLimitMiddleware(w *WAF, limit float64, burst int, ban time.Duration) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		waf:               w,
		limit:             rate.Limit(limit),
		burst:             burst,
		banDuration:       ban,
		multiplier:        2.0,
		violationResetTTL: 24 * time.Hour,
	}
}

func (m *RateLimitMiddleware) push(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.waf == nil {
			next.ServeHTTP(w, r)
			return
		}

		id := extractIP(r.RemoteAddr)

		// Quick check for banned ids
		if m.waf.bans.IsBanned(id) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		st := m.waf.states.Get(id)
		if st == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Ensure limiter exists and has desired parameters
		st.mu.Lock()
		if st.Limiter == nil || st.currentLimit != m.limit || st.currentBurst != m.burst {
			st.Limiter = rate.NewLimiter(m.limit, m.burst)
			st.currentLimit = m.limit
			st.currentBurst = m.burst
		}
		allowed := st.Limiter.Allow()
		st.LastSeen = time.Now()
		st.mu.Unlock()

		// Set basic rate headers
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(m.burst))

		if !allowed {
			// Rate limit exceeded: calculate dynamic ban duration based on violation history
			st.mu.Lock()
			now := time.Now()

			// Check if violation counter should be reset (too much time passed since last violation)
			if !st.LastViolationTime.IsZero() && now.Sub(st.LastViolationTime) > m.violationResetTTL {
				st.RateLimitViolations = 0
			}

			// Increment violation counter
			st.RateLimitViolations++
			st.LastViolationTime = now

			// Calculate ban duration: base * (multiplier ^ violations)
			// For multiplier=2: 1st ban=30s, 2nd=60s, 3rd=120s, 4th=240s, etc.
			banDuration := time.Duration(float64(m.banDuration) * math.Pow(m.multiplier, float64(st.RateLimitViolations-1)))
			violationCount := st.RateLimitViolations
			st.mu.Unlock()

			// Ban and respond 429
			m.waf.bans.Ban(id, banDuration)
			w.Header().Set("Retry-After", strconv.FormatInt(int64(banDuration.Seconds()), 10))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			log.Printf("[%s] Rate limit exceeded for %s: banned for %s (violation #%d)", now.Format(time.RFC3339), id, banDuration, violationCount)
			return
		}

		next.ServeHTTP(w, r)
	})
}

