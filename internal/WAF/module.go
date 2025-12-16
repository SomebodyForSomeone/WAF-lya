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


	middlewares := []Middleware{
		&SomeCheck{},
	}

	var handler http.Handler = httputil.NewSingleHostReverseProxy(target)
	for _, middleware := range middlewares {
		handler = middleware.push(handler)
	}


	log.Printf("Attemp to create Reverse Proxy on the post %s with redirecting to %s", port, targetAddress)
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatalln("Error on starting Reverse Proxy:", err)
	}
	log.Println("Successful")
}


type Middleware interface {
	push(h http.Handler) http.Handler
}


type SomeCheck struct {}
func (m *SomeCheck) push(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("New request: %s", r.RemoteAddr)

		next.ServeHTTP(w, r)

		/// Do smth
	})
}
