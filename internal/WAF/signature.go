package waf

import (
	"errors"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
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

		// Кандидаты на анализ: path, raw query
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
					log.Printf("[%s] Обнаружена атака SQLi от %s: payload -> %s", time.Now().Format(time.RFC3339), ip, normalized)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if m.isXSS(normalized) {
				if m.logMatches {
					log.Printf("[%s] Обнаружена атака XSS от %s: payload -> %s", time.Now().Format(time.RFC3339), ip, normalized)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if m.ptPatterns != nil && isPathTraversal(normalized, m.ptPatterns) {
				if m.logMatches {
					log.Printf("[%s] Обнаружена атака обхода путей от %s: payload -> %s", time.Now().Format(time.RFC3339), ip, normalized)
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

// isPathTraversal проверяет строку на path traversal по паттернам (регулярные выражения)
func isPathTraversal(s string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			// Если паттерн невалидный, пропускаем
			continue
		}
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// // isSQLi использует libinjection-go для проверки SQL-инъекций
// func isSQLi(s string) bool {
// 	found, _ := libinjection.IsSQLi(s)
// 	return found
// }

// // isXSS использует libinjection-go для проверки XSS
// func isXSS(s string) bool {
// 	// Сначала libinjection-go
// 	return libinjection.IsXSS(s)
// }

// decodeBypassSequences декодирует обходные последовательности (overlong UTF-8, hex, смешанные)
func decodeBypassSequences(s string) string {
	// Overlong UTF-8 для / и .
	overlongReplacements := map[string]string{
		"%c0%af": "/", "%c0%ae": ".",
		"%e0%80%af": "/", "%e0%80%ae": ".",
		"%f0%80%80%af": "/", "%f0%80%80%ae": ".",
		"%c0%2f": "/", "%c0%5c": "\\", "%c0%2e": ".",
		"%c0.%c0./": "../", "%c0.%c0.%5c": "..\\",
	}
	for k, v := range overlongReplacements {
		s = strings.ReplaceAll(s, k, v)
		s = strings.ReplaceAll(s, strings.ToUpper(k), v)
	}
	// Декодированные байты
	s = strings.ReplaceAll(s, "\xc0\xaf", "/")
	s = strings.ReplaceAll(s, "\xc0\xae", ".")
	s = strings.ReplaceAll(s, "\xe0\x80\xaf", "/")
	s = strings.ReplaceAll(s, "\xe0\x80\xae", ".")
	s = strings.ReplaceAll(s, "\xf0\x80\x80\xaf", "/")
	s = strings.ReplaceAll(s, "\xf0\x80\x80\xae", ".")
	s = strings.ReplaceAll(s, "\xc0\x2f", "/")
	s = strings.ReplaceAll(s, "\xc0\x5c", "\\")
	s = strings.ReplaceAll(s, "\xc0\x2e", ".")

	// Hex-последовательности: 0x2e (.), 0x2f (/), 0x5c (\)
	hexRe := regexp.MustCompile(`0x([0-9a-fA-F]{2})`)
	s = hexRe.ReplaceAllStringFunc(s, func(match string) string {
		hex := match[2:]
		if b, err := strconv.ParseUint(hex, 16, 8); err == nil {
			switch b {
			case 0x2e:
				return "."
			case 0x2f:
				return "/"
			case 0x5c:
				return "\\"
			default:
				return string(rune(b))
			}
		}
		return match
	})

	// Смешанные варианты: %c0.%c0./, %c0.%c0.%5c и т.д.
	s = strings.ReplaceAll(s, "%c0.%c0./", "../")
	s = strings.ReplaceAll(s, "%c0.%c0.%5c", "..\\")
	s = strings.ReplaceAll(s, "%c0.%c0%2f", "../")
	s = strings.ReplaceAll(s, "%c0.%c0%5c", "..\\")

	return s
}

// normalizeForSignature нормализует запрос для проверки сигнатур.
// Декодирует, удаляет комментарии, приводит к нижнему регистру.
func normalizeForSignature(s string) string {
	// Декодирование обходных последовательностей (overlong, hex, смешанные)
	s = decodeBypassSequences(s)
	if s == "" {
		return ""
	}

	// Рекурсивное URL-декодирование (до 5 раз)
	for i := 0; i < 5; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
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
