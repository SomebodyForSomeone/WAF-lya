package waf

import (
	"errors"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	patternparser "github.com/SomebodyForSomeone/WAF-lya/internal/pattern_parser"
	libinjection "github.com/corazawaf/libinjection-go"
)

// LoadPatternsFromFile загружает паттерны из текстового файла (по одному на строку)
func LoadPatternsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var patterns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, nil
}

// LoadPatternsDynamic загружает паттерны через PatternParser
// sourceType: "file" или "url"
func LoadPatternsDynamic(sourceType, source, format string) ([]string, error) {
	switch format {
	case "txt":
		if sourceType == "file" {
			return patternparser.ParseTxtPatternsFromFile(source)
		} else if sourceType == "url" {
			return patternparser.ParseTxtPatternsFromURL(source)
		}
		return nil, errors.New("unsupported source type: " + sourceType)
	default:
		return nil, errors.New("unsupported pattern format: " + format)
	}
}

// SignatureMiddleware обнаруживает атаки (SQLi, XSS, path traversal)
// Блокирует запрос, но не блокирует IP
type SignatureMiddleware struct {
	waf          *WAF
	logMatches   bool
	ptPatterns   []string
	xssPatterns  []string
	sqliPatterns []string
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

		// Собрать кандидаты для анализа: path, raw query, значения query-параметров
		candidates := []string{r.URL.Path, r.URL.RawQuery}

		// Добавить значения всех query-параметров
		for param, values := range r.URL.Query() {
			for _, v := range values {
				// Добавить имя и значение параметра для анализа
				candidates = append(candidates, param)
				candidates = append(candidates, v)
			}
		}

		// Нормализовать каждого кандидата
		for i, s := range candidates {
			candidates[i] = normalizeForSignature(s)
		}

		// Проверка через libinjection-go, XSS и path traversal паттерны
		for _, normalized := range candidates {
			if m.isSQLi(normalized) {
				if m.logMatches {
					log.Printf("[%s] Обнаружена атака SQLi от %s: payload=%s", time.Now().Format(time.RFC3339), ip, normalized)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if m.isXSS(normalized) {
				if m.logMatches {
					log.Printf("[%s] Обнаружена атака XSS от %s: payload=%s", time.Now().Format(time.RFC3339), ip, normalized)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if m.ptPatterns != nil && isPathTraversal(normalized, m.ptPatterns) {
				if m.logMatches {
					log.Printf("[%s] Обнаружена атака обхода путей от %s: payload=%s", time.Now().Format(time.RFC3339), ip, normalized)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		// Запрос прошел проверку сигнатур
		next.ServeHTTP(w, r)
	})
}

// NewSignatureMiddlewareWithPathTraversal создает SignatureMiddleware с паттернами path traversal
func NewSignatureMiddlewareWithPathTraversal(w *WAF, ptPatterns []string) *SignatureMiddleware {
	xssPatterns, err := LoadPatternsDynamic("file", "patterns/xss.txt", "txt")
	if err != nil {
		log.Printf("[WAF] Ошибка загрузки XSS паттернов: %v", err)
	}
	sqliPatterns, err := LoadPatternsDynamic("file", "patterns/sqli.txt", "txt")
	if err != nil {
		log.Printf("[WAF] Ошибка загрузки SQLi паттернов: %v", err)
	}
	return &SignatureMiddleware{
		waf:          w,
		ptPatterns:   ptPatterns,
		xssPatterns:  xssPatterns,
		sqliPatterns: sqliPatterns,
		logMatches:   true,
	}

}

// Метод для проверки SQLi с учётом паттернов из файла
func (m *SignatureMiddleware) isSQLi(s string) bool {
	found, _ := libinjection.IsSQLi(s)
	if found {
		return true
	}
	s = strings.ToLower(s)
	for _, pat := range m.sqliPatterns {
		if pat == "" {
			continue
		}
		if strings.Contains(s, pat) {
			return true
		}
	}
	return false
}

// Метод для проверки XSS с учётом паттернов из файла
func (m *SignatureMiddleware) isXSS(s string) bool {
	if libinjection.IsXSS(s) {
		return true
	}
	s = strings.ToLower(s)
	for _, pat := range m.xssPatterns {
		if pat == "" {
			continue
		}
		if strings.Contains(s, pat) {
			return true
		}
	}
	return false
}

// isPathTraversal проверяет строку на path traversal по паттернам
func isPathTraversal(s string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// isSQLi использует libinjection-go для проверки SQL-инъекций
func isSQLi(s string) bool {
	found, _ := libinjection.IsSQLi(s)
	return found
}

// isXSS использует libinjection-go для проверки XSS
func isXSS(s string) bool {
	// Сначала libinjection-go
	return libinjection.IsXSS(s)
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
