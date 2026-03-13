package waf

// Структуры конфигурации WAF
type RateLimitConfig struct {
	Limit             float64 `json:"limit"`
	Burst             int     `json:"burst"`
	BanSeconds        int     `json:"ban_seconds"`
	Multiplier        float64 `json:"multiplier"`
	ViolationResetHrs int     `json:"violation_reset_hours"`
}

type SignatureConfig struct {
	LogMatches bool `json:"log_matches"`
}

type ContextConfig struct {
	WindowSeconds       int     `json:"window_seconds"`
	Threshold           int     `json:"threshold"`
	BanSeconds          int     `json:"ban_seconds"`
	Multiplier          float64 `json:"multiplier"`
	ViolationResetHours int     `json:"violation_reset_hours"`
}

type Config struct {
	RateLimit                       RateLimitConfig             `json:"rate_limit"`
	Signature                       SignatureConfig             `json:"signature"`
	Context                         ContextConfig               `json:"context"`
	MiddlewareChain                 []string                    `json:"middleware_chain"`
	WAFPort                         string                      `json:"waf_port"`
	ServerAddress                   string                      `json:"server_address"`
	PathTraversalPatternsPath       string                      `json:"path_traversal_patterns_path"`
	PathTraversalPatternsSource     PathTraversalPatternsSource `json:"path_traversal_patterns_source"`
	PathTraversalPatternsSourceFile PathTraversalPatternsSource `json:"path_traversal_patterns_source_file"`
}

type PathTraversalPatternsSource struct {
	SourceType string `json:"source_type"`
	Source     string `json:"source"`
	Format     string `json:"format"`
}
