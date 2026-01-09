package waf

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Core WAF types and initialization live here. Filtering modules
// should be implemented in separate files and register as Middleware.

type Middleware interface {
	push(h http.Handler) http.Handler
}

// State represents per-identifier (IP / session) data kept by WAF.
type State struct {
	ID        string
	LastSeen  time.Time
	Limiter   *rate.Limiter
	Meta      map[string]interface{}
	mu        sync.Mutex
}

// stateStore manages concurrent access to State objects.
type stateStore struct {
	store sync.Map // map[string]*State
}

func newStateStore() *stateStore { return &stateStore{} }

func (s *stateStore) Get(id string) *State {
	if id == "" {
		return nil
	}
	if v, ok := s.store.Load(id); ok {
		return v.(*State)
	}
	// create default state with a token bucket limiter
	st := &State{
		ID:       id,
		LastSeen: time.Now(),
		Limiter:  rate.NewLimiter(rate.Limit(5), 20),
		Meta:     make(map[string]interface{}),
	}
	s.store.Store(id, st)
	return st
}

// banList contains temporarily banned identifiers with expiry.
type banEntry struct{
	until time.Time
}

type banList struct{
	m sync.Map // map[string]banEntry
}

func newBanList() *banList { return &banList{} }

func (b *banList) IsBanned(id string) bool {
	if v, ok := b.m.Load(id); ok {
		e := v.(banEntry)
		if time.Now().Before(e.until) {
			return true
		}
		b.m.Delete(id)
	}
	return false
}

func (b *banList) Ban(id string, d time.Duration) {
	b.m.Store(id, banEntry{until: time.Now().Add(d)})
}

// WAF is the main container: holds config, state and middleware chain.
type WAF struct{
	target *url.URL
	proxy  *httputil.ReverseProxy

	middlewares []Middleware
	states      *stateStore
	bans        *banList
}

// NewWAF builds a WAF instance for the given upstream address.
func NewWAF(targetAddr string) (*WAF, error) {
	target, err := url.Parse(targetAddr)
	if err != nil {
		return nil, err
	}
	return &WAF{
		target: target,
		proxy:  httputil.NewSingleHostReverseProxy(target),
		states: newStateStore(),
		bans:   newBanList(),
	}, nil
}

// RegisterMiddleware appends a middleware to the chain.
func (w *WAF) RegisterMiddleware(m Middleware) {
	w.middlewares = append(w.middlewares, m)
}

// Handler constructs the http.Handler by wrapping the reverse proxy
// with the registered middlewares (last registered runs first).
func (w *WAF) Handler() http.Handler {
	var handler http.Handler = w.proxy
	// apply in reverse so that first registered is outermost
	for i := len(w.middlewares)-1; i >= 0; i-- {
		handler = w.middlewares[i].push(handler)
	}
	return handler
}

// Run convenience: create WAF, register default modules and start server.
func Run(port, targetAddress string) {
	waf, err := NewWAF(targetAddress)
	if err != nil {
		log.Fatalln("Error parsing target URL:", err)
	}

	// register example middleware — real filters should be in separate files
	waf.RegisterMiddleware(&SomeCheck{waf: waf})

	handler := waf.Handler()

	log.Printf("Starting Reverse Proxy on port %s -> %s", port, targetAddress)
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatalln("Error on starting Reverse Proxy:", err)
	}
}

// extractIP normalizes r.RemoteAddr into host-only form.
func extractIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		// could be already without port
		return remote
	}
	return host
}

// SomeCheck is a minimal example middleware. Replace / extend in modules.
type SomeCheck struct{ waf *WAF }

func (m *SomeCheck) push(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r.RemoteAddr)

		// quick bancheck
		if m.waf != nil && m.waf.bans.IsBanned(ip) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// update state last-seen and rate limit
		if m.waf != nil {
			st := m.waf.states.Get(ip)
			st.mu.Lock()
			st.LastSeen = time.Now()
			allowed := st.Limiter.Allow()
			st.mu.Unlock()
			if !allowed {
				// simple ban-on-excess example
				m.waf.bans.Ban(ip, 30*time.Second)
				w.Header().Set("Retry-After", "30")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		log.Printf("Request from %s %s %s", ip, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
