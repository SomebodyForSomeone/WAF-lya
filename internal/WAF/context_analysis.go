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
	resourceExtractor ContextResourceExtractorConfig
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
func NewContextMiddlewareWithConfig(w *WAF, window time.Duration, threshold int, banDuration time.Duration, extractor ContextResourceExtractorConfig) *ContextMiddleware {
	return &ContextMiddleware{
		waf:               w,
		window:            window,
		threshold:         threshold,
		banDuration:       banDuration,
		multiplier:        2.0,
		violationResetTTL: 24 * time.Hour,
		logDetections:     true,
		resourceExtractor: extractor,
	}
}

// extractResourceID извлекает идентификатор ресурса из запроса.
// Если extractor не задан, используется дефолтная логика проекта.
func (m *ContextMiddleware) extractResourceID(r *http.Request) string {
	switch m.resourceExtractor.Type {
	case "":
		return extractResourceIDDefault(r)
	case "query_param":
		return strings.TrimSpace(r.URL.Query().Get(m.resourceExtractor.Name))
	case "path_segment":
		return extractPathSegmentByName(r.URL.Path, m.resourceExtractor.Name)
	case "last_segment":
		return extractLastPathSegment(r.URL.Path)
	case "last_numeric_segment":
		return extractLastNumericPathSegment(r.URL.Path)
	default:
		if m.logDetections {
			log.Printf("[WAF] Неизвестный тип извлечения ресурса для context: %s. Используется логика по умолчанию", m.resourceExtractor.Type)
		}
		return extractResourceIDDefault(r)
	}
}

// extractResourceIDDefault ихвлечение id из url.
func extractResourceIDDefault(r *http.Request) string {
	resource := strings.TrimSpace(r.URL.Query().Get("id"))
	if resource != "" {
		return resource
	}
	return extractLastNumericPathSegment(r.URL.Path)
}

// extractPathSegmentByName ищет сегмент пути по имени и возвращает следующий за ним.
// Например, для /api/users/42 при имени users будет возвращено 42.
func extractPathSegmentByName(path, name string) string {
	name = strings.Trim(strings.TrimSpace(name), "/")
	if name == "" {
		return ""
	}
	parts := splitPathSegments(path)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == name {
			return parts[i+1]
		}
	}
	return ""
}

// extractLastPathSegment возвращает последний непустой сегмент пути.
func extractLastPathSegment(path string) string {
	parts := splitPathSegments(path)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// extractLastNumericPathSegment возвращает последний числовой сегмент пути.
func extractLastNumericPathSegment(path string) string {
	last := extractLastPathSegment(path)
	if last == "" {
		return ""
	}
	if _, err := strconv.Atoi(last); err == nil {
		return last
	}
	return ""
}

// splitPathSegments разбивает путь на непустые сегменты.
func splitPathSegments(path string) []string {
	rawParts := strings.Split(strings.Trim(path, "/"), "/")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
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

		// Использовалось ранее
		session := r.Header.Get("X-Session-ID")
		if session == "" {
			if c, err := r.Cookie("sessionid"); err == nil {
				session = c.Value
			}
		}

		// Извлечь идентификатор ресурса из запроса
		resource := m.extractResourceID(r)

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

		// Установить время последнего доступ к ресурсу
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

		// Сброс счетчика BOLA только если TTL истек
		st.mu.Lock()
		var lastBolaViolationTime time.Time
		if v, ok := st.Meta["last_bola_violation_time"]; ok {
			lastBolaViolationTime = v.(time.Time)
		}
		now = time.Now()
		if !lastBolaViolationTime.IsZero() && now.Sub(lastBolaViolationTime) > m.violationResetTTL {
			st.Meta["bola_violations"] = 0
			st.Meta["last_bola_violation_time"] = time.Time{}
		}
		st.mu.Unlock()

		// Отслеживание сессии
		_ = session

		next.ServeHTTP(w, r)
	})
}
