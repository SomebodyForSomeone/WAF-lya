package main

import (
	"os"

	waf "github.com/SomebodyForSomeone/WAF-lya/internal/WAF"
)

const defaultWAFPort string = ":8000"
const defaultTargetAddress string = "http://localhost:8081"
const defaultConfigPath string = "waf_config.json"

func main() {
	// Путь к конфигу из аргумента, переменной окружения или по умолчанию
	configPath := defaultConfigPath
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else if envPath := os.Getenv("WAF_CONFIG"); envPath != "" {
		configPath = envPath
	}

	// Загрузить конфиг
	cfg, err := waf.LoadConfig(configPath)
	if err != nil {
		panic(err)
	}

	// Использовать значения из конфига или по умолчанию
	wafPort := defaultWAFPort
	targetAddress := defaultTargetAddress

	if cfg != nil {
		if cfg.WAFPort != "" {
			wafPort = cfg.WAFPort
		}
		if cfg.ServerAddress != "" {
			targetAddress = cfg.ServerAddress
		}
	}

	waf.RunWithConfig(wafPort, targetAddress, configPath)
}
