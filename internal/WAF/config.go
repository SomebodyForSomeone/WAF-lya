package waf

import (
	"encoding/json"
	"os"
)

// Структуры конфигурации WAF
type RateLimitConfig struct {
    Limit             float64 `json:"limit"`
    Burst             int     `json:"burst"`
    BanSeconds        int     `json:"ban_seconds"`
    Multiplier        float64 `json:"multiplier"`
    ViolationResetHrs int     `json:"violation_reset_hours"`
}

type SignatureConfig struct {
    LogMatches bool   `json:"log_matches"`
}

type ContextConfig struct {
	WindowSeconds         int     `json:"window_seconds"`
	Threshold             int     `json:"threshold"`
	BanSeconds            int     `json:"ban_seconds"`
	Multiplier            float64 `json:"multiplier"`
	ViolationResetHours   int     `json:"violation_reset_hours"`
}

type Config struct {
    MiddlewareChain []string       `json:"middleware_chain"`
    RateLimit       RateLimitConfig `json:"rate_limit"`
    Signature       SignatureConfig `json:"signature"`
    Context         ContextConfig  `json:"context"`
    WAFPort         string         `json:"waf_port"`
    ServerAddress   string         `json:"server_address"`
    SignaturePatternsPath string   `json:"signature_patterns_path"`
}

// LoadConfig загружает конфиг из JSON. При отсутствии файла возвращает nil.
func LoadConfig(path string) (*Config, error) {
    if path == "" {
        return nil, nil
    }
    data, err := os.ReadFile(path)
    if err != nil {
        // treat missing file as no config
        return nil, nil
    }
    var c Config
    if err := json.Unmarshal(data, &c); err != nil {
        return nil, err
    }
    return &c, nil
}
