package waf

import (
	"encoding/json"
	"os"
)

// LoadConfig загружает конфиг из JSON. При отсутствии файла возвращает nil
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// нет файла = нет конфига
		return nil, nil
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
