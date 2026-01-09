package main

import (
	waf "github.com/SomebodyForSomeone/WAF-lya/internal/WAF"
)


const wafPort string = ":8000"
const targetAddress string = "http://localhost:8081"


func main() {
	// look for waf_config.json in the project root (optional)
	waf.RunWithConfig(wafPort, targetAddress, "waf_config.json")
}
