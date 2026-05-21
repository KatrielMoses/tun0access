// Package backend defines the plug-in interface every VPN provider implements
// and the registry that lets the CLI iterate over all enabled providers.
package backend

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Server is a single endpoint a Backend can connect us to.
type Server struct {
	// ID is unique within a backend (hostname, public key, etc.).
	ID string
	// Backend is the name of the source backend ("vpngate", "protonvpn", ...).
	Backend string
	// CountryLong is the human-readable country name ("United States").
	CountryLong string
	// CountryShort is the ISO-3166 alpha-2 code, uppercase ("US").
	CountryShort string
	// City is optional — populated when the backend exposes it.
	City string
	// Host is the public host or IP.
	Host string
	// Score is a backend-specific quality heuristic (higher = better).
	Score int64
	// PingMS is the reported ping in milliseconds, 0 if unknown.
	PingMS int
	// SpeedBps is the reported speed in bytes per second, 0 if unknown.
	SpeedBps int64
	// Protocol is "openvpn" or "wireguard".
	Protocol string
	// Config is the raw provider config (decoded .ovpn text or wg-quick text).
	Config []byte
	// Credentials are optional. When non-nil the runner writes them to a temp
	// auth-user-pass file and passes --auth-user-pass to openvpn.
	Credentials *Credentials
}

// Credentials holds a username/password pair for backends that require
// shared or per-account auth (e.g. VPNBook, ProtonVPN free).
type Credentials struct {
	Username string
	Password string
}

// Backend is implemented by every VPN provider plug-in.
type Backend interface {
	// Name is the short identifier ("vpngate", "protonvpn-free").
	Name() string
	// Fetch returns the current list of usable servers. Implementations
	// should cache aggressively and respect ctx cancellation.
	Fetch(ctx context.Context) ([]Server, error)
}

var (
	mu       sync.RWMutex
	backends = map[string]Backend{}
)

// Register makes a backend available to the CLI. Call from init().
func Register(b Backend) {
	mu.Lock()
	defer mu.Unlock()
	backends[b.Name()] = b
}

// All returns every registered backend, sorted by name for stable output.
func All() []Backend {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Backend, 0, len(backends))
	for _, b := range backends {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// FetchAll queries every registered backend concurrently and merges the
// results. Partial failures are returned in errs but do not abort the call.
func FetchAll(ctx context.Context) (servers []Server, errs []error) {
	all := All()
	if len(all) == 0 {
		return nil, []error{fmt.Errorf("no VPN backends registered")}
	}

	type result struct {
		s []Server
		e error
		n string
	}
	ch := make(chan result, len(all))
	var wg sync.WaitGroup
	for _, b := range all {
		wg.Add(1)
		go func(b Backend) {
			defer wg.Done()
			s, err := b.Fetch(ctx)
			ch <- result{s: s, e: err, n: b.Name()}
		}(b)
	}
	wg.Wait()
	close(ch)

	for r := range ch {
		if r.e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.n, r.e))
			continue
		}
		servers = append(servers, r.s...)
	}
	return servers, errs
}

// GroupByCountry returns servers indexed by ISO country code, with each
// country's slice sorted by Score descending (best first).
func GroupByCountry(servers []Server) map[string][]Server {
	out := map[string][]Server{}
	for _, s := range servers {
		out[s.CountryShort] = append(out[s.CountryShort], s)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].Score > out[k][j].Score })
	}
	return out
}
