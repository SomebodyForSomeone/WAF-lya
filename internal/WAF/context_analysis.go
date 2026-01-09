package waf

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ContextMiddleware — шаблон для stateful анализа взаимодействий
// (например обнаружение перебора ResourceID / BOLA).
type ContextMiddleware struct{
    waf *WAF
    // window — временное окно для подсчёта уникальных ResourceID
    window time.Duration
    // threshold — допустимое количество уникальных ресурсов в окне
    threshold int
}

func NewContextMiddleware(w *WAF) *ContextMiddleware {
    return &ContextMiddleware{waf: w, window: 60 * time.Second, threshold: 20}
}

func (m *ContextMiddleware) push(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if m.waf == nil {
            next.ServeHTTP(w, r)
            return
        }

        id := extractIP(r.RemoteAddr)
        if m.waf.bans.IsBanned(id) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        st := m.waf.states.Get(id)
        if st == nil {
            next.ServeHTTP(w, r)
            return
        }

        // Попытка извлечь SessionID (из заголовка или cookie)
        session := r.Header.Get("X-Session-ID")
        if session == "" {
            if c, err := r.Cookie("sessionid"); err == nil {
                session = c.Value
            }
        }

        // Извлечение ResourceID из query param 'id' или числовой части пути
        resource := r.URL.Query().Get("id")
        if resource == "" {
            parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
            if len(parts) > 0 {
                // последний сегмент может быть числом
                last := parts[len(parts)-1]
                if _, err := strconv.Atoi(last); err == nil {
                    resource = last
                }
            }
        }

        // Обновление состояния: храним карту resource->lastSeen
        st.mu.Lock()
        now := time.Now()
        // meta key 'resources' хранит map[string]time.Time
        var resources map[string]time.Time
        if v, ok := st.Meta["resources"]; ok {
            resources = v.(map[string]time.Time)
        } else {
            resources = make(map[string]time.Time)
        }
        if resource != "" {
            resources[resource] = now
        }
        // очистка старых записей
        for k, t := range resources {
            if now.Sub(t) > m.window {
                delete(resources, k)
            }
        }
        st.Meta["resources"] = resources
        st.LastSeen = now
        st.mu.Unlock()

        // Анализ аномалий: если уникальных ресурсов больше порога — событие
        if len(resources) > m.threshold {
            log.Printf("BOLA-like behavior detected for %s: %d unique resources", id, len(resources))
            // решение: временная блокировка и логирование
            m.waf.bans.Ban(id, 5*time.Minute)
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        // Можно дополнительно сохранять session->visited mapping
        _ = session // placeholder for further logic

        next.ServeHTTP(w, r)
    })
}
