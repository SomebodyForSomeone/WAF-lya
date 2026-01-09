package waf

import (
	"log"
	"net/http"
	"time"
)

// RateLimitMiddleware — шаблон фильтра, реализующий политику Token Bucket.
// Настройки лимита можно вынести в конфиг. По превышению — добавляет в banlist.
type RateLimitMiddleware struct{
    waf *WAF
    // defaultRate и burst могут быть сделаны на уровне конфигурации
    defaultBan time.Duration
}

func NewRateLimitMiddleware(w *WAF) *RateLimitMiddleware {
    return &RateLimitMiddleware{waf: w, defaultBan: 30 * time.Second}
}

func (m *RateLimitMiddleware) push(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if m.waf == nil {
            next.ServeHTTP(w, r)
            return
        }

        id := extractIP(r.RemoteAddr)

        // quick skip for whitelisted or already banned handled elsewhere
        if m.waf.bans.IsBanned(id) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        st := m.waf.states.Get(id)
        if st == nil {
            next.ServeHTTP(w, r)
            return
        }

        st.mu.Lock()
        allowed := st.Limiter.Allow()
        st.LastSeen = time.Now()
        st.mu.Unlock()

        if !allowed {
            // при превышении — временная блокировка и ответ 429
            m.waf.bans.Ban(id, m.defaultBan)
            w.Header().Set("Retry-After", "30")
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            log.Printf("Rate limit exceeded for %s: banned for %s", id, m.defaultBan)
            return
        }

        next.ServeHTTP(w, r)
    })
}
