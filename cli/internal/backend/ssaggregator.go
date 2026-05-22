package backend

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KatrielMoses/tun0access/internal/geoip"
	"github.com/KatrielMoses/tun0access/internal/proxy"
)

// SSAggregator pulls free SS / VMess / VLESS / Trojan configs from public
// GitHub subscription repos, deduplicates by host:port, GeoIP-tags each
// endpoint, and emits one Server per parseable URI.
//
// The current MVP source is freefq/free's `v2` subscription. The fetcher is
// stateless on its sources list, so adding more is a one-line append.
type SSAggregator struct {
	HTTP *http.Client
	Geo  *geoip.Resolver

	mu       sync.Mutex
	cache    []Server
	cachedAt time.Time
}

// sources are the URLs we pull subscription data from. Each entry is
// expected to either be plain newline-separated URIs or a single base64 blob
// that decodes to the same.
var sources = []string{
	"https://raw.githubusercontent.com/freefq/free/master/v2",
	"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
	"https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
	"https://raw.githubusercontent.com/learnhard-cn/free_proxy_ss/main/free",
	"https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
	"https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
}

func NewSSAggregator() *SSAggregator {
	return &SSAggregator{
		HTTP: &http.Client{Timeout: 30 * time.Second},
		Geo:  geoip.New(),
	}
}

func (a *SSAggregator) Name() string { return "ss-aggregator" }

// cacheTTL is short because the upstream lists rotate multiple times per day.
const aggregatorCacheTTL = 30 * time.Minute

func (a *SSAggregator) Fetch(ctx context.Context) ([]Server, error) {
	a.mu.Lock()
	if time.Since(a.cachedAt) < aggregatorCacheTTL && len(a.cache) > 0 {
		out := a.cache
		a.mu.Unlock()
		return out, nil
	}
	a.mu.Unlock()

	// Pull all sources concurrently.
	type sourceResult struct {
		uris []string
		err  error
	}
	resCh := make(chan sourceResult, len(sources))
	for _, url := range sources {
		go func(u string) {
			uris, err := a.fetchSource(ctx, u)
			resCh <- sourceResult{uris: uris, err: err}
		}(url)
	}
	var allURIs []string
	for range sources {
		r := <-resCh
		if r.err == nil {
			allURIs = append(allURIs, r.uris...)
		}
	}

	// Parse + deduplicate by server:port.
	type parsed struct {
		uri string
		out *proxy.Outbound
	}
	seen := map[string]struct{}{}
	var items []parsed
	for _, u := range allURIs {
		o, err := proxy.Parse(u)
		if err != nil || o == nil {
			continue
		}
		key := fmt.Sprintf("%s:%d", o.Server, o.ServerPort)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, parsed{uri: u, out: o})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("ss-aggregator: no parseable URIs found across %d source(s)", len(sources))
	}

	// GeoIP-tag every unique host.
	hosts := make([]string, 0, len(items))
	for _, it := range items {
		hosts = append(hosts, it.out.Server)
	}
	geoMap := a.Geo.ResolveMany(ctx, hosts)

	// Materialize Server entries.
	var servers []Server
	for _, it := range items {
		geo := geoMap[it.out.Server]
		if geo.CountryCode == "" {
			continue // skip hosts we couldn't locate; UI would group them under "??"
		}
		cfgJSON, err := json.Marshal(it.out)
		if err != nil {
			continue
		}
		servers = append(servers, Server{
			ID:           fmt.Sprintf("ss:%s:%d", it.out.Server, it.out.ServerPort),
			Backend:      "ss-aggregator",
			CountryLong:  geo.CountryName,
			CountryShort: geo.CountryCode,
			Host:         it.out.Server,
			Score:        25, // baseline; health checker will rerank these
			Protocol:     it.out.Protocol,
			Config:       cfgJSON,
		})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("ss-aggregator: parsed %d URIs but GeoIP returned 0 countries", len(items))
	}

	a.mu.Lock()
	a.cache = servers
	a.cachedAt = time.Now()
	a.mu.Unlock()
	return servers, nil
}

// fetchSource pulls one URL, base64-decodes the body if it looks like a
// subscription wrapper, and returns the list of URI lines.
func (a *SSAggregator) fetchSource(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}

	// If body is a single base64 blob (no scheme prefix in the first 32 bytes),
	// decode once.
	preview := strings.TrimSpace(string(body))
	if !strings.HasPrefix(preview, "ss://") &&
		!strings.HasPrefix(preview, "vmess://") &&
		!strings.HasPrefix(preview, "vless://") &&
		!strings.HasPrefix(preview, "trojan://") {
		if dec, err := decodeAny(preview); err == nil {
			body = []byte(dec)
		}
	}

	var uris []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ss://") ||
			strings.HasPrefix(line, "vmess://") ||
			strings.HasPrefix(line, "vless://") ||
			strings.HasPrefix(line, "trojan://") {
			uris = append(uris, line)
		}
	}
	return uris, nil
}

// decodeAny tries every common base64 variant to handle the inconsistent
// padding/charset choices these free-sub sources use.
func decodeAny(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if d, err := enc.DecodeString(s); err == nil {
			return string(d), nil
		}
	}
	return "", fmt.Errorf("not valid base64")
}

func init() { Register(NewSSAggregator()) }
