package waf

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func Run(port, targetAddress string) {
	target, err := url.Parse(targetAddress)
	if err != nil {
		log.Fatalln("Error on parsing target URL:", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	log.Printf("Attemp to create Reverse Proxy on the post %s with redirecting to %s", port, targetAddress)
	if err := http.ListenAndServe(port, proxy); err != nil {
		log.Fatalln("Error on starting Reverse Proxy:", err)
	}
	log.Println("Successful")
}
