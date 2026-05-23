// Package geoip resolves server IPs/hostnames to ISO country codes.
//
// We use ip-api.com's batch endpoint — free, no key required, 100 IPs per
// POST, ~14 batches/min on the free tier. The batch endpoint only accepts
// IPs (it returns status:fail for hostnames), so we DNS-resolve hostnames
// first. To make that scale, the resolution is done concurrently with a
// worker pool. Results are cached in-memory AND on disk so subsequent CLI
// invocations within ~24h reuse the lookup.
package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	apiURL          = "http://ip-api.com/batch?fields=status,country,countryCode,query"
	batchSize       = 100
	httpTimeout     = 15 * time.Second
	dnsTimeout      = 3 * time.Second
	dnsConcurrency  = 50
	diskCacheMaxAge = 24 * time.Hour
)

// Result is what we cache per host.
type Result struct {
	CountryCode string
	CountryName string
}

// Resolver is a country-code lookup cache that batches requests.
type Resolver struct {
	HTTP *http.Client

	mu    sync.RWMutex
	cache map[string]Result // key: original host string
}

// New constructs a Resolver and warms the in-memory cache from disk.
func New() *Resolver {
	r := &Resolver{
		HTTP:  &http.Client{Timeout: httpTimeout},
		cache: map[string]Result{},
	}
	r.loadFromDisk()
	return r
}

// ResolveMany looks up an arbitrary list of hosts. The returned map is keyed
// by the original host string. Hostnames are DNS-resolved in parallel; IPs
// are queried via ip-api.com in batches of 100. Cache hits short-circuit
// everything. Persists the cache to disk on completion.
func (r *Resolver) ResolveMany(ctx context.Context, hosts []string) map[string]Result {
	out := map[string]Result{}

	// 1. Cache lookup.
	var notCached []string
	for _, h := range hosts {
		if h == "" {
			continue
		}
		r.mu.RLock()
		c, ok := r.cache[h]
		r.mu.RUnlock()
		if ok {
			out[h] = c
			continue
		}
		notCached = append(notCached, h)
	}
	notCached = dedup(notCached)
	if len(notCached) == 0 {
		return out
	}

	// 2. Concurrent DNS: hostname → IP. IPs pass through unchanged.
	hostToIP := resolveHostsParallel(ctx, notCached, dnsConcurrency)

	// 3. Collect unique IPs needing API lookup.
	ipSet := map[string]struct{}{}
	for _, ip := range hostToIP {
		if ip != "" {
			ipSet[ip] = struct{}{}
		}
	}
	ipsToQuery := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipsToQuery = append(ipsToQuery, ip)
	}

	// 4. Batch ip-api.com lookups. On 429 the loop just keeps going — those
	// IPs will be missing from ipToResult and the hosts get empty results
	// (still better than blocking).
	ipToResult := map[string]Result{}
	for i := 0; i < len(ipsToQuery); i += batchSize {
		end := i + batchSize
		if end > len(ipsToQuery) {
			end = len(ipsToQuery)
		}
		results, err := r.batch(ctx, ipsToQuery[i:end])
		if err != nil {
			continue
		}
		for ip, res := range results {
			ipToResult[ip] = res
		}
	}

	// 5. Fill output, populate cache.
	r.mu.Lock()
	for h, ip := range hostToIP {
		var res Result
		if ip != "" {
			res = ipToResult[ip]
		}
		out[h] = res
		r.cache[h] = res
	}
	r.mu.Unlock()

	// 6. Persist (best-effort).
	r.saveToDisk()
	return out
}

func resolveHostsParallel(ctx context.Context, hosts []string, workers int) map[string]string {
	result := make(map[string]string, len(hosts))
	var mu sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			ip := toIP(ctx, host)
			mu.Lock()
			result[host] = ip
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return result
}

type batchEntry struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Query       string `json:"query"`
}

func (r *Resolver) batch(ctx context.Context, ips []string) (map[string]Result, error) {
	body, _ := json.Marshal(ips)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var entries []batchEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("ip-api decode: %w", err)
	}
	out := map[string]Result{}
	for _, e := range entries {
		if e.Status != "success" {
			out[e.Query] = Result{}
			continue
		}
		out[e.Query] = Result{
			CountryCode: strings.ToUpper(e.CountryCode),
			CountryName: e.Country,
		}
	}
	return out, nil
}

// toIP returns the dotted IPv4 form for a host. If the input is already an
// IP, it is returned as-is. Hostname lookups have a short timeout so a
// hung resolver doesn't stall the batch.
func toIP(parent context.Context, host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	ctx, cancel := context.WithTimeout(parent, dnsTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func dedup(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ── disk persistence ────────────────────────────────────────────────────

type diskCache struct {
	SavedAt time.Time         `json:"saved_at"`
	Entries map[string]Result `json:"entries"`
}

func cacheFile() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "tun0access", "cache", "geoip.json")
		}
	case "darwin":
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, "Library", "Caches", "tun0access", "geoip.json")
		}
	default:
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, ".cache", "tun0access", "geoip.json")
		}
	}
	return ""
}

func (r *Resolver) loadFromDisk() {
	path := cacheFile()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var dc diskCache
	if err := json.Unmarshal(data, &dc); err != nil {
		return
	}
	if time.Since(dc.SavedAt) > diskCacheMaxAge {
		return
	}
	r.mu.Lock()
	for k, v := range dc.Entries {
		r.cache[k] = v
	}
	r.mu.Unlock()
}

func (r *Resolver) saveToDisk() {
	path := cacheFile()
	if path == "" {
		return
	}
	r.mu.RLock()
	// Only persist successful lookups. Empty Results stay in-memory (so the
	// current process doesn't re-query within a single CLI invocation) but
	// don't pollute future runs — important when a transient rate-limit
	// briefly causes everything to look unresolvable.
	snapshot := make(map[string]Result, len(r.cache))
	for k, v := range r.cache {
		if v.CountryCode == "" {
			continue
		}
		snapshot[k] = v
	}
	r.mu.RUnlock()
	data, err := json.Marshal(diskCache{SavedAt: time.Now(), Entries: snapshot})
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, data, 0o600)
}
