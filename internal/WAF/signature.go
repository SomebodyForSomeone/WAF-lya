package waf

import (
	"html"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SignatureMiddleware обнаруживает известные атаки (SQLi, XSS, path traversal).
// Блокирует запрос, но не блокирует IP (бан только для rate-limit и BOLA).
type SignatureMiddleware struct{
	waf        *WAF
	rules      []*regexp.Regexp
	logMatches bool
}

// NewSignatureMiddleware создает анализатор с встроенными сигнатурами.
func NewSignatureMiddleware(w *WAF) *SignatureMiddleware {
	patterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter)\s+(\*|[a-z_]+)`,
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)javascript:`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)\.\.[\\\/]`, // path traversal
	}
	return newSignatureMiddlewareWithPatterns(w, patterns)
}

// NewSignatureMiddlewareWithPatterns создает анализатор с кастомными сигнатурами.
func NewSignatureMiddlewareWithPatterns(w *WAF, patterns []string) *SignatureMiddleware {
	return newSignatureMiddlewareWithPatterns(w, patterns)
}

// newSignatureMiddlewareWithPatterns компилирует regex паттерны.
func newSignatureMiddlewareWithPatterns(w *WAF, patterns []string) *SignatureMiddleware {
	regs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			regs = append(regs, re)
		} else {
			log.Printf("Warning: invalid signature pattern: %v", err)
		}
	}
	return &SignatureMiddleware{
		waf:        w,
		rules:      regs,
		logMatches: true,
	}
}

func (m *SignatureMiddleware) push(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.waf == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r.RemoteAddr)

		// Проверка бана
		if m.waf.bans.IsBanned(ip) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Собрать candidates для анализа: path и query string
		candidates := []string{r.URL.Path, r.URL.RawQuery}

		// Нормализовать каждый candidate
		for i, s := range candidates {
			candidates[i] = normalizeForSignature(s)
		}

		// Проверить против зарегистрированных сигнатур
		for _, normalized := range candidates {
			for _, rule := range m.rules {
				if rule.MatchString(normalized) {
				// Совпадение: блокировать, но не блокировать IP.
					if m.logMatches {
						log.Printf("[%s] Signature attack detected from %s: rule=%s, payload=%s", time.Now().Format(time.RFC3339), ip, rule.String(), normalized)
					}
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// Запрос прошел проверку сигнатур
		next.ServeHTTP(w, r)
	})
}

// normalizeForSignature нормализует запрос для проверки сигнатур.
// Декодирует, удаляет комментарии, приводит к нижнему регистру.
func normalizeForSignature(s string) string {
	if s == "" {
		return ""
	}

	// URL-декодирование
	if decoded, err := url.QueryUnescape(s); err == nil {
		s = decoded
	}

	// Раскодирование HTML сущностей
	s = html.UnescapeString(s)

	// Привести к нижнему регистру
	s = strings.ToLower(s)

	// Удалить пробелы в начале и конце
	s = strings.TrimSpace(s)

	// Свернуть множество пробелов в один
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")

	// Удалить SQL комментарии (/* ... */)
	s = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(s, "")

	// Удалить SQL комментарии строк (-- ...)
	s = regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(s, "")

	// Удалить HTML комментарии (<!-- ... -->)
	s = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(s, "")

	return s
}
