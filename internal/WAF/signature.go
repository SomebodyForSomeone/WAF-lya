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

// SignatureMiddleware implements static signature-based attack pattern detection.
// Normalizes request data (URL, query, headers) and matches against regex rules.
type SignatureMiddleware struct{
	waf          *WAF
	rules        []*regexp.Regexp
	banDuration  time.Duration
	logMatches   bool
}

// NewSignatureMiddleware creates a signature analyzer with given patterns.
// Invalid regex patterns are logged and skipped.
func newDefaultSignatureMiddleware(w *WAF, patterns []string) *SignatureMiddleware {
	regs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			regs = append(regs, re)
		} else {
			log.Printf("Warning: invalid signature pattern: %v", err)
		}
	}
	return &SignatureMiddleware{
		waf:         w,
		rules:       regs,
		banDuration: 5 * time.Minute,
		logMatches:  true,
	}
}

// NewDefaultSignatureMiddleware creates a signature analyzer with built-in patterns
// for common attacks: SQL injection, XSS, and path traversal.
func NewSignatureMiddleware(w *WAF) *SignatureMiddleware {
	patterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter)\s+(\*|[a-z_]+)`,
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)javascript:`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)\.\.[\\\/]`, // path traversal
	}
	return newDefaultSignatureMiddleware(w, patterns)
}

func (m *SignatureMiddleware) push(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.waf == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r.RemoteAddr)

		// Quick check for already banned identifier
		if m.waf.bans.IsBanned(ip) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Collect candidates for analysis: path and query string
		candidates := []string{r.URL.Path, r.URL.RawQuery}

		// Normalize each candidate
		for i, s := range candidates {
			candidates[i] = normalizeForSignature(s)
		}

		// Check against all registered patterns
		for _, normalized := range candidates {
			for _, rule := range m.rules {
				if rule.MatchString(normalized) {
					// Pattern matched: ban the identifier and log
					m.waf.bans.Ban(ip, m.banDuration)
					if m.logMatches {
						log.Printf("Signature attack detected from %s: rule=%s, payload=%s", ip, rule.String(), normalized)
					}
					w.Header().Set("Retry-After", "300")
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// Request passed signature checks
		next.ServeHTTP(w, r)
	})
}

// normalizeForSignature normalizes request data for pattern matching.
// Applies: URL-decode, HTML entity unescape, lowercase, space collapse, comment removal.
func normalizeForSignature(s string) string {
	if s == "" {
		return ""
	}

	// URL-decode
	if decoded, err := url.QueryUnescape(s); err == nil {
		s = decoded
	}

	// HTML entity unescape
	s = html.UnescapeString(s)

	// Convert to lowercase for case-insensitive matching
	s = strings.ToLower(s)

	// Trim leading/trailing whitespace
	s = strings.TrimSpace(s)

	// Collapse multiple spaces to single space
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")

	// Remove SQL comments (/* ... */)
	s = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(s, "")

	// Remove SQL line comments (-- ...)
	s = regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(s, "")

	// Remove HTML comments (<!-- ... -->)
	s = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(s, "")

	return s
}
