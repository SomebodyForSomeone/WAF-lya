package waf

import (
	"encoding/json"
	"os"
)

// Configuration structures for WAF
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
    WindowSeconds int `json:"window_seconds"`
    Threshold     int `json:"threshold"`
    BanSeconds    int `json:"ban_seconds"`
}

type Config struct {
    MiddlewareChain []string       `json:"middleware_chain"`
    RateLimit       RateLimitConfig `json:"rate_limit"`
    Signature       SignatureConfig `json:"signature"`
    Context         ContextConfig  `json:"context"`
}

// LoadConfig reads JSON config from path. If path is empty or file not found, returns nil, nil.
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
