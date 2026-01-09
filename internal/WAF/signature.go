package waf

import (
	"html"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// SignatureMiddleware — шаблон для статического сигнатурного анализа.
// Реализует нормализацию и сопоставление с правилами (регекспы).
type SignatureMiddleware struct{
    waf   *WAF
    rules []*regexp.Regexp
}

func NewSignatureMiddleware(w *WAF, patterns []string) *SignatureMiddleware {
    regs := make([]*regexp.Regexp, 0, len(patterns))
    for _, p := range patterns {
        // при ошибке компиляции можно логировать и игнорировать правило
        if re, err := regexp.Compile(p); err == nil {
            regs = append(regs, re)
        }
    }
    return &SignatureMiddleware{waf: w, rules: regs}
}

func (m *SignatureMiddleware) push(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // быстрый бан-чек
        if m.waf != nil {
            ip := extractIP(r.RemoteAddr)
            if m.waf.bans.IsBanned(ip) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
        }

        // Собираем строки для анализа: path, query, заголовки
        candidates := []string{r.URL.Path, r.URL.RawQuery}
        // Нормализация каждой строки
        for i, s := range candidates {
            candidates[i] = normalizeForSignature(s)
        }

        // Проверяем по регекспам
        for _, s := range candidates {
            for _, re := range m.rules {
                if re.MatchString(s) {
                    // при срабатывании — можно добавлять в банлист или логировать
                    ip := extractIP(r.RemoteAddr)
                    if m.waf != nil {
                        m.waf.bans.Ban(ip, 60*1*1e9) // placeholder: 60s
                    }
                    log.Printf("Signature match from %s: %s", ip, re.String())
                    http.Error(w, "Forbidden", http.StatusForbidden)
                    return
                }
            }
        }

        // TODO: добавить нечёткий поиск (fuzzy) — вынести в отдельный пакет
        next.ServeHTTP(w, r)
    })
}

// normalizeForSignature приводит строку в вид, удобный для сопоставления:
// unescape URL, convert HTML entities, to lower-case and trim spaces.
func normalizeForSignature(s string) string {
    if s == "" { return "" }
    // URL-decode
    if decoded, err := url.QueryUnescape(s); err == nil {
        s = decoded
    }
    // HTML entities
    s = html.UnescapeString(s)
    // lower-case and collapse spaces
    s = strings.ToLower(s)
    s = strings.TrimSpace(s)
    // remove simple SQL/HTML comments (very basic)
    s = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(s, "")
    s = regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(s, "")
    return s
}
