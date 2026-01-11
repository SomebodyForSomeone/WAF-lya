package main

import (
	"os"

	waf "github.com/SomebodyForSomeone/WAF-lya/internal/WAF"
)

const defaultWAFPort string = ":8000"
const defaultTargetAddress string = "http://localhost:8081"
const defaultConfigPath string = "waf_config.json"

func main() {
	// Get config path from command line arg or env var or default
	configPath := defaultConfigPath
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else if envPath := os.Getenv("WAF_CONFIG"); envPath != "" {
		configPath = envPath
	}

	// Load config to get ports and addresses
	cfg, err := waf.LoadConfig(configPath)
	if err != nil {
		panic(err)
	}

	// Use config values or defaults
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
