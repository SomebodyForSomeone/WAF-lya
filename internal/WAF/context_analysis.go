package waf

import (
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ContextMiddleware анализирует аномалии поведения пользователя (BOLA, сканирование)
// Отслеживает уникальные ресурсы за временное окно
type ContextMiddleware struct {
	waf               *WAF
	window            time.Duration
	threshold         int
	banDuration       time.Duration
	multiplier        float64
	violationResetTTL time.Duration
	logDetections     bool
}

// NewContextMiddleware создает анализатор контекста с дефолт настройками
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

// NewContextMiddlewareWithConfig создает анализатор с кастомными настройками
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

		// Извлечь ID сессии из заголовка или кука
		session := r.Header.Get("X-Session-ID")
		if session == "" {
			if c, err := r.Cookie("sessionid"); err == nil {
				session = c.Value
			}
		}

		// Извлечь ID ресурса из параметра 'id' или числового сегмента пути
		resource := r.URL.Query().Get("id")
		if resource == "" {
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				// Проверить, числовой ли последний сегмент пути
				if _, err := strconv.Atoi(last); err == nil {
					resource = last
				}
			}
		}

		// Обновить состояние: карта доступов к ресурсам с временем
		st.mu.Lock()
		now := time.Now()

		// Инициализировать или получить карту ресурсов
		var resources map[string]time.Time
		if v, ok := st.Meta["resources"]; ok {
			resources = v.(map[string]time.Time)
		} else {
			resources = make(map[string]time.Time)
		}

		// Записать доступ к ресурсу
		if resource != "" {
			resources[resource] = now
		}

		// Удалить старые записи вне временного окна
		for k, t := range resources {
			if now.Sub(t) > m.window {
				delete(resources, k)
			}
		}

		st.Meta["resources"] = resources
		st.LastSeen = now
		st.mu.Unlock()

		// Анализ аномалий: срабатывание при превышении порога
		uniqueCount := len(resources)
		if uniqueCount > m.threshold {
			st.mu.Lock()
			now := time.Now()

			// Сброс счетчика нарушений через установленное время
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

			// Увеличить счетчик нарушений
			bolaViolations++
			st.Meta["bola_violations"] = bolaViolations
			st.Meta["last_bola_violation_time"] = now

			// Вычислить длительность бана
			banDuration := time.Duration(float64(m.banDuration) * math.Pow(m.multiplier, float64(bolaViolations-1)))
			violationCount := bolaViolations
			st.mu.Unlock()

			m.waf.bans.Ban(id, banDuration)
			if m.logDetections {
				log.Printf("[%s] Обнаружено поведение, похожее на BOLA, от %s: %d уникальных ресурсов за %s, заблокирован на %s (нарушение #%d)", now.Format(time.RFC3339), id, uniqueCount, m.window, banDuration, violationCount)
			}
			w.Header().Set("Retry-After", strconv.FormatInt(int64(banDuration.Seconds()), 10))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Сброс счетчика BOLA при успешном запросе
		st.mu.Lock()
		st.Meta["bola_violations"] = 0
		st.Meta["last_bola_violation_time"] = time.Time{}
		st.mu.Unlock()

		// Отслеживание сессии
		_ = session

		next.ServeHTTP(w, r)
	})
}
