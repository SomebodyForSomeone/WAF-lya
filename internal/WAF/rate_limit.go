package waf

import (
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitMiddleware реализует token-bucket лимитер. При превышении блокирует IP.
// Повторные нарушения удлиняют бан экспоненциально.
type RateLimitMiddleware struct{
	waf               *WAF
	limit             rate.Limit
	burst             int
	banDuration       time.Duration
	multiplier        float64       // ban duration multiplier on repeat offenses (default 2.0)
	violationResetTTL time.Duration // reset violation counter after this duration (default 24h)
}

// NewRateLimitMiddleware создает rate-limiter middleware.
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

		// Проверка бана
		if m.waf.bans.IsBanned(id) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		st := m.waf.states.Get(id)
		if st == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Проверить лимитер и его параметры
		st.mu.Lock()
		if st.Limiter == nil || st.currentLimit != m.limit || st.currentBurst != m.burst {
			st.Limiter = rate.NewLimiter(m.limit, m.burst)
			st.currentLimit = m.limit
			st.currentBurst = m.burst
		}
		allowed := st.Limiter.Allow()
		st.LastSeen = time.Now()
		st.mu.Unlock()

		// Установить заголовки rate limit
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(m.burst))

		if !allowed {
			// Rate limit превышен: вычислить динамическую длительность бана
			st.mu.Lock()
			now := time.Now()

				// Сброс счетчика если истек period_reset
			if !st.LastViolationTime.IsZero() && now.Sub(st.LastViolationTime) > m.violationResetTTL {
				st.RateLimitViolations = 0
			}

				// Увеличить счетчик нарушений
			st.RateLimitViolations++
			st.LastViolationTime = now

				// Вычислить: base * (multiplier ^ violations)
			banDuration := time.Duration(float64(m.banDuration) * math.Pow(m.multiplier, float64(st.RateLimitViolations-1)))
			violationCount := st.RateLimitViolations
			st.mu.Unlock()

			// Заблокировать и вернуть 429
			m.waf.bans.Ban(id, banDuration)
			w.Header().Set("Retry-After", strconv.FormatInt(int64(banDuration.Seconds()), 10))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			log.Printf("[%s] Rate limit exceeded for %s: banned for %s (violation #%d)", now.Format(time.RFC3339), id, banDuration, violationCount)
			return
		}

		next.ServeHTTP(w, r)
	})
}

