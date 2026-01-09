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
	ID              string
	LastSeen        time.Time
	Limiter         *rate.Limiter
	Meta            map[string]interface{}
	RateLimitViolations int       // count of consecutive rate-limit bans
	LastViolationTime   time.Time // timestamp of last rate-limit violation
	mu              sync.Mutex
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

// Run convenience: create WAF, register default protection modules and start server.
func Run(port, targetAddress string) {
	RunWithConfig(port, targetAddress, "")
}

// RunWithConfig creates WAF, registers middleware according to JSON config (if provided), and starts server.
// configPath may be empty to use defaults.
func RunWithConfig(port, targetAddress, configPath string) {
	waf, err := NewWAF(targetAddress)
	if err != nil {
		log.Fatalln("Error parsing target URL:", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalln("Error loading config:", err)
	}

	// Determine middleware chain: use config order if provided, otherwise sensible default
	chain := []string{"context", "rate_limit", "signature"}
	if cfg != nil && len(cfg.MiddlewareChain) > 0 {
		chain = cfg.MiddlewareChain
	}

	for _, name := range chain {
		switch name {
		case "rate_limit":
			// defaults
			rl := NewRateLimitMiddleware(waf, 5.0, 20, 30*time.Second)
			if cfg != nil {
				rlc := cfg.RateLimit
				if rlc.Limit > 0 {
					rl.limit = rate.Limit(rlc.Limit)
				}
				if rlc.Burst > 0 {
					rl.burst = rlc.Burst
				}
				if rlc.BanSeconds > 0 {
					rl.banDuration = time.Duration(rlc.BanSeconds) * time.Second
				}
				if rlc.Multiplier > 0 {
					rl.multiplier = rlc.Multiplier
				}
				if rlc.ViolationResetHrs > 0 {
					rl.violationResetTTL = time.Duration(rlc.ViolationResetHrs) * time.Hour
				}
			}
			waf.RegisterMiddleware(rl)

		case "signature":
			// Signature patterns are defined inside the signature module.
			sm := NewSignatureMiddleware(waf)
			if cfg != nil {
				sm.logMatches = cfg.Signature.LogMatches
			}
			waf.RegisterMiddleware(sm)

		case "context":
			if cfg != nil && cfg.Context.WindowSeconds > 0 {
				cm := NewContextMiddlewareWithConfig(waf, time.Duration(cfg.Context.WindowSeconds)*time.Second, cfg.Context.Threshold, time.Duration(cfg.Context.BanSeconds)*time.Second)
				// Apply dynamic throttling settings from config
				if cfg.Context.Multiplier > 0 {
					cm.multiplier = cfg.Context.Multiplier
				}
				if cfg.Context.ViolationResetHours > 0 {
					cm.violationResetTTL = time.Duration(cfg.Context.ViolationResetHours) * time.Hour
				}
				waf.RegisterMiddleware(cm)
			} else {
				waf.RegisterMiddleware(NewContextMiddleware(waf))
			}

		case "somecheck":
			waf.RegisterMiddleware(&SomeCheck{waf: waf})

		default:
			// ignore unknown names
			log.Printf("Unknown middleware in chain: %s (skipped)", name)
		}
	}

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
