package waf

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitMiddleware implements a token-bucket rate limiter per identifier
// (IP/session). On exceed it adds the identifier to the banlist.
type RateLimitMiddleware struct{
    waf        *WAF
    limit      rate.Limit
    burst      int
    banDuration time.Duration
}

// NewRateLimitMiddleware creates a rate limiter middleware.
// `limit` is requests per second, `burst` is bucket capacity, `ban` is ban duration on exceed.
func NewRateLimitMiddleware(w *WAF, limit float64, burst int, ban time.Duration) *RateLimitMiddleware {
    return &RateLimitMiddleware{waf: w, limit: rate.Limit(limit), burst: burst, banDuration: ban}
}

func (m *RateLimitMiddleware) push(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if m.waf == nil {
            next.ServeHTTP(w, r)
            return
        }

        id := extractIP(r.RemoteAddr)

        // quick check for banned ids
        if m.waf.bans.IsBanned(id) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        st := m.waf.states.Get(id)
        if st == nil {
            next.ServeHTTP(w, r)
            return
        }

        // ensure limiter exists and has desired parameters
        st.mu.Lock()
        if st.Limiter == nil {
            st.Limiter = rate.NewLimiter(m.limit, m.burst)
        }
        // Note: we don't replace existing limiter to preserve burst state across requests.
        allowed := st.Limiter.Allow()
        st.LastSeen = time.Now()
        st.mu.Unlock()

        // set basic rate headers
        w.Header().Set("X-RateLimit-Limit", strconv.Itoa(m.burst))

        if !allowed {
            // ban and respond 429
            m.waf.bans.Ban(id, m.banDuration)
            w.Header().Set("Retry-After", strconv.FormatInt(int64(m.banDuration.Seconds()), 10))
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            log.Printf("Rate limit exceeded for %s: banned for %s", id, m.banDuration)
            return
        }

        next.ServeHTTP(w, r)
    })
}

