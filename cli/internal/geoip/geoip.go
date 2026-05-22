// Package geoip resolves server IPs/hostnames to ISO country codes.
//
// We use ip-api.com's batch endpoint — free, no key required, 100 IPs per
// POST, rate-limit ~15 req/min for the free tier. With batching this handles
// thousands of servers in seconds.
package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	apiURL      = "http://ip-api.com/batch?fields=status,country,countryCode,query"
	batchSize   = 100
	httpTimeout = 15 * time.Second
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
	cache map[string]Result
}

func New() *Resolver {
	return &Resolver{
		HTTP:  &http.Client{Timeout: httpTimeout},
		cache: map[string]Result{},
	}
}

// ResolveMany looks up an arbitrary list of hosts (hostnames or IPs). It
// returns a map keyed by the original host string. Hostnames are resolved to
// an A record first; lookups that fail return an empty Result rather than an
// error so the caller can decide whether to skip those servers.
func (r *Resolver) ResolveMany(ctx context.Context, hosts []string) map[string]Result {
	out := map[string]Result{}

	// First pass: pull from cache, normalize hostnames → IPs.
	var toQuery []string
	hostToIP := map[string]string{}
	for _, h := range hosts {
		ip := toIP(h)
		hostToIP[h] = ip
		if ip == "" {
			out[h] = Result{}
			continue
		}
		r.mu.RLock()
		c, ok := r.cache[ip]
		r.mu.RUnlock()
		if ok {
			out[h] = c
			continue
		}
		toQuery = append(toQuery, ip)
	}
	toQuery = dedup(toQuery)

	// Second pass: batch what's left.
	for i := 0; i < len(toQuery); i += batchSize {
		end := i + batchSize
		if end > len(toQuery) {
			end = len(toQuery)
		}
		results, err := r.batch(ctx, toQuery[i:end])
		if err != nil {
			continue // best-effort; let those hosts return empty
		}
		r.mu.Lock()
		for ip, res := range results {
			r.cache[ip] = res
		}
		r.mu.Unlock()
	}

	// Third pass: fill in remaining results from the now-warmed cache.
	for h, ip := range hostToIP {
		if _, ok := out[h]; ok {
			continue
		}
		r.mu.RLock()
		out[h] = r.cache[ip]
		r.mu.RUnlock()
	}
	return out
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
// IP, it is returned as-is. If it's a hostname, a DNS lookup is performed
// (with a short timeout) and the first A record is returned. Returns "" on
// failure.
func toIP(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip4", host)
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
