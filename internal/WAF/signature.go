package waf

import (
	"bufio"
	"context"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const regexTimeout = 100 * time.Millisecond // лимит времени на один паттерн
const maliciousPatternsFile = "patterns/malicious.txt"

// saveMaliciousPattern сохраняет вредоносный паттерн в файл
func saveMaliciousPattern(pattern string) {
	f, err := os.OpenFile(maliciousPatternsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to save malicious pattern: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(pattern + "\n"); err != nil {
		log.Printf("Failed to write malicious pattern: %v", err)
	}
}

// safeMatchString проверяет строку на совпадение с паттерном с таймаутом
func safeMatchString(re *regexp.Regexp, s string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), regexTimeout)
	defer cancel()
	ch := make(chan bool, 1)
	go func() {
		ch <- re.MatchString(s)
	}()
	select {
	case res := <-ch:
		return res, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// SignatureMiddleware обнаруживает известные атаки (SQLi, XSS, path traversal).
// Блокирует запрос, но не блокирует IP (бан только для rate-limit и BOLA).
type SignatureMiddleware struct{
	waf        *WAF
	rules      []*regexp.Regexp
	logMatches bool
}

// LoadPatternsFromFile загружает паттерны из текстового файла (по одному на строку)
func LoadPatternsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return patterns, nil
}

// LoadMultiplePatternFiles загружает паттерны из нескольких файлов и объединяет их
func LoadMultiplePatternFiles(paths []string) ([]string, error) {
	var allPatterns []string
	for _, path := range paths {
		patterns, err := LoadPatternsFromFile(path)
		if err != nil {
			log.Printf("Pattern loading error from %s: %v", path, err)
			continue
		}
		allPatterns = append(allPatterns, patterns...)
	}
	return allPatterns, nil
}

// NewSignatureMiddlewareFromFile создает SignatureMiddleware, загружая паттерны из файла
func NewSignatureMiddlewareFromFile(w *WAF, path string) *SignatureMiddleware {
	patterns, err := LoadPatternsFromFile(path)
	if err != nil {
		log.Printf("Pattern loading error: %v", err)
		patterns = []string{}
	}
	return newSignatureMiddlewareWithPatterns(w, patterns)
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
			for i := 0; i < len(m.rules); i++ {
				rule := m.rules[i]
				matched, err := safeMatchString(rule, normalized)
				if err != nil {
					log.Printf("[WAF] Warning: pattern %s took too long to execute and was removed", rule.String())
					saveMaliciousPattern(rule.String())
					// Удалить паттерн из списка
					m.rules = append(m.rules[:i], m.rules[i+1:]...)
					i-- // скорректировать индекс после удаления
					continue
				}
				if matched {
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
