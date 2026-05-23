// Package cdncheck flags whether a server IP or hostname belongs to a CDN /
// anycast network. Free Trojan / VMess / VLESS configs frequently point at
// Cloudflare-fronted domains; the TLS handshake then terminates at the CDN
// edge nearest to the *user*, so a "Hong Kong" server actually exits in
// (whatever POP is closest to the user's ISP). Catching these at ingest
// time lets us relabel them as `Anycast / CDN-fronted` instead of lying
// about the country.
//
// Detection sources, free + keyless:
//   - Cloudflare: https://www.cloudflare.com/ips-v4 + /ips-v6 (text, one CIDR per line)
//   - Fastly:     https://api.fastly.com/public-ip-list (JSON)
//   - AWS:        https://ip-ranges.amazonaws.com/ip-ranges.json (JSON, filtered to service=CLOUDFRONT)
//   - Hostname suffix patterns for serverless CDN entry points (workers.dev,
//     pages.dev, cloudfront.net, etc.) handled purely offline.
package cdncheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// rangesCacheTTL — how long we trust a cached upstream fetch before
// re-downloading. The lists themselves change infrequently (weeks).
const rangesCacheTTL = 24 * time.Hour

// Detector answers "is this IP / hostname behind a CDN?"
type Detector struct {
	mu      sync.RWMutex
	loaded  bool
	ranges  []provNet // CIDR set, with provider name attached
	loadErr error
}

// New returns a Detector. It does NOT fetch ranges on construction — first
// call triggers the load. Use Prepare() to warm it explicitly.
func New() *Detector { return &Detector{} }

type provNet struct {
	prefix   netip.Prefix
	provider string
}

// Prepare eagerly loads CDN ranges (from disk cache when fresh, falling back
// to upstream fetch). Safe to call from a goroutine before traffic starts.
func (d *Detector) Prepare() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.loaded {
		return d.loadErr
	}
	d.loaded = true
	rs, err := loadOrFetch()
	if err != nil {
		// Even on failure we keep the bundled fallback so detection still
		// works in degraded mode rather than silently false-negative.
		rs = append(rs, bundledFallback()...)
		d.loadErr = err
	}
	d.ranges = rs
	return d.loadErr
}

// IsCDN reports whether ip is inside any known CDN range. Returns the
// provider name on match ("cloudflare" / "fastly" / "cloudfront").
func (d *Detector) IsCDN(ip netip.Addr) (bool, string) {
	if !ip.IsValid() {
		return false, ""
	}
	if err := d.Prepare(); err != nil {
		// Continue with whatever we managed to load (incl. bundled fallback).
		_ = err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, r := range d.ranges {
		if r.prefix.Contains(ip) {
			return true, r.provider
		}
	}
	return false, ""
}

// IsCDNHost reports whether host's suffix matches a known CDN serverless /
// edge pattern (workers.dev, pages.dev, cloudfront.net, etc.). This catches
// configs that don't have an IP to check yet (or whose A record is a CDN
// but the hostname is the more obvious tell). Pure string match, no network.
func (d *Detector) IsCDNHost(host string) (bool, string) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range hostnamePatterns {
		if strings.HasSuffix(h, p.suffix) {
			return true, p.provider
		}
	}
	return false, ""
}

// Detect runs both checks. Host is the original hostname (or IP literal);
// ip is the resolved IP (may be invalid if resolution failed, in which case
// only the hostname check runs).
func (d *Detector) Detect(host string, ip netip.Addr) (bool, string) {
	if ok, prov := d.IsCDNHost(host); ok {
		return true, prov
	}
	if ok, prov := d.IsCDN(ip); ok {
		return true, prov
	}
	return false, ""
}

// ── upstream fetchers ───────────────────────────────────────────────────

func loadOrFetch() ([]provNet, error) {
	if rs, ok := loadFromDisk(); ok {
		return rs, nil
	}
	rs, err := fetchAll()
	if err != nil {
		return rs, err
	}
	saveToDisk(rs)
	return rs, nil
}

func fetchAll() ([]provNet, error) {
	type srcResult struct {
		rs  []provNet
		err error
	}
	results := make(chan srcResult, 4)

	go func() {
		rs, err := fetchCloudflareV4()
		results <- srcResult{rs, err}
	}()
	go func() {
		rs, err := fetchCloudflareV6()
		results <- srcResult{rs, err}
	}()
	go func() {
		rs, err := fetchFastly()
		results <- srcResult{rs, err}
	}()
	go func() {
		rs, err := fetchCloudFront()
		results <- srcResult{rs, err}
	}()

	var combined []provNet
	var firstErr error
	for i := 0; i < 4; i++ {
		r := <-results
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		combined = append(combined, r.rs...)
	}
	return combined, firstErr
}

func fetchTextLines(url, provider string) ([]provNet, error) {
	body, err := httpGet(url, 8*time.Second)
	if err != nil {
		return nil, err
	}
	var out []provNet
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		out = append(out, provNet{prefix: p, provider: provider})
	}
	return out, nil
}

func fetchCloudflareV4() ([]provNet, error) {
	return fetchTextLines("https://www.cloudflare.com/ips-v4", "cloudflare")
}

func fetchCloudflareV6() ([]provNet, error) {
	return fetchTextLines("https://www.cloudflare.com/ips-v6", "cloudflare")
}

func fetchFastly() ([]provNet, error) {
	body, err := httpGet("https://api.fastly.com/public-ip-list", 8*time.Second)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("fastly decode: %w", err)
	}
	var out []provNet
	for _, c := range append(resp.Addresses, resp.IPv6Addresses...) {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, provNet{prefix: p, provider: "fastly"})
		}
	}
	return out, nil
}

func fetchCloudFront() ([]provNet, error) {
	body, err := httpGet("https://ip-ranges.amazonaws.com/ip-ranges.json", 10*time.Second)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("aws decode: %w", err)
	}
	var out []provNet
	for _, p := range resp.Prefixes {
		if p.Service != "CLOUDFRONT" {
			continue
		}
		if pr, err := netip.ParsePrefix(p.IPPrefix); err == nil {
			out = append(out, provNet{prefix: pr, provider: "cloudfront"})
		}
	}
	for _, p := range resp.IPv6Prefixes {
		if p.Service != "CLOUDFRONT" {
			continue
		}
		if pr, err := netip.ParsePrefix(p.IPv6Prefix); err == nil {
			out = append(out, provNet{prefix: pr, provider: "cloudfront"})
		}
	}
	return out, nil
}

func httpGet(url string, timeout time.Duration) ([]byte, error) {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// ── disk cache ──────────────────────────────────────────────────────────

type cacheFile struct {
	SavedAt time.Time `json:"saved_at"`
	Entries []struct {
		Prefix   string `json:"p"`
		Provider string `json:"v"`
	} `json:"entries"`
}

func cachePath() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "tun0access", "cache", "cdn-ranges.json")
		}
	case "darwin":
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, "Library", "Caches", "tun0access", "cdn-ranges.json")
		}
	default:
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, ".cache", "tun0access", "cdn-ranges.json")
		}
	}
	return ""
}

func loadFromDisk() ([]provNet, bool) {
	p := cachePath()
	if p == "" {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, false
	}
	if time.Since(cf.SavedAt) > rangesCacheTTL {
		return nil, false
	}
	out := make([]provNet, 0, len(cf.Entries))
	for _, e := range cf.Entries {
		pre, err := netip.ParsePrefix(e.Prefix)
		if err != nil {
			continue
		}
		out = append(out, provNet{prefix: pre, provider: e.Provider})
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func saveToDisk(rs []provNet) {
	p := cachePath()
	if p == "" {
		return
	}
	cf := cacheFile{SavedAt: time.Now()}
	for _, r := range rs {
		cf.Entries = append(cf.Entries, struct {
			Prefix   string `json:"p"`
			Provider string `json:"v"`
		}{r.prefix.String(), r.provider})
	}
	data, err := json.Marshal(cf)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, data, 0o600)
}

// ── hostname patterns + bundled fallback ────────────────────────────────

type hostPattern struct {
	suffix   string // matched via strings.HasSuffix (case-insensitive)
	provider string
}

// Common serverless / CDN entry hostnames. Free-config repos frequently
// point at these because their owners host the Trojan/VLESS backend on a
// free PaaS that's CDN-fronted.
var hostnamePatterns = []hostPattern{
	// Cloudflare
	{".workers.dev", "cloudflare"},
	{".pages.dev", "cloudflare"},
	{".trycloudflare.com", "cloudflare"},
	{".r2.dev", "cloudflare"},
	{".cdn.cloudflare.net", "cloudflare"},
	{".cloudflare-ipfs.com", "cloudflare"},
	{".cloudflareaccess.com", "cloudflare"},
	// AWS
	{".cloudfront.net", "cloudfront"},
	{".execute-api.amazonaws.com", "aws"},
	// Fastly
	{".fastly.net", "fastly"},
	{".fastlylb.net", "fastly"},
	// Akamai
	{".akamaiedge.net", "akamai"},
	{".akamaized.net", "akamai"},
	{".akamaihd.net", "akamai"},
	// Google (App Engine / Cloud Run / Firebase Hosting are anycast-fronted)
	{".appspot.com", "google"},
	{".run.app", "google"},
	{".web.app", "google"},
	{".firebaseapp.com", "google"},
	// Netlify / Vercel (used as VLESS/Trojan fronts in some configs)
	{".netlify.app", "netlify"},
	{".vercel.app", "vercel"},
}

// bundledFallback is a tiny hard-coded set of the most-fronted ranges so
// detection still works when every upstream fetch fails. Intentionally
// minimal — just Cloudflare's /20s, which catch the bulk of the lie.
func bundledFallback() []provNet {
	out := []provNet{}
	for _, c := range []string{
		// Cloudflare IPv4 (as of 2026 — slow-changing)
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		// Cloudflare IPv6
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
		"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
		"2c0f:f248::/32",
	} {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, provNet{prefix: p, provider: "cloudflare"})
		}
	}
	return out
}
