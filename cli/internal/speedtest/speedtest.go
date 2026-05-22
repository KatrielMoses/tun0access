// Package speedtest measures real throughput through whatever tunnel is
// currently up. We download a known-size payload from Cloudflare's speed
// endpoint and time it.
//
// Critically, the probe targets a pre-resolved IP rather than a hostname.
// Once the tunnel comes up, DNS queries are routed through the proxy and
// failures look like "no such host" even though it's really the proxy
// timing out. Pre-resolving outside the tunnel removes DNS from the
// measurement and gives us a true TCP throughput reading.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// Cloudflare's speed endpoint. Anycast — many IPs serve it.
	probeHost = "speed.cloudflare.com"

	// Hardcoded fallback IP if pre-resolution fails. Cloudflare's anycast
	// range — these IPs are extremely stable.
	fallbackProbeIP = "162.159.135.79"

	defaultPayloadBytes = 200_000
	defaultTimeout      = 10 * time.Second
	defaultSettleDelay  = 600 * time.Millisecond

	// MinUsableMbps is "is this server actually browsable?" threshold.
	// 0.5 Mbps ≈ 60 KB/s — slow but workable for text-mostly browsing.
	MinUsableMbps = 0.5
)

var (
	probeIPMu sync.Mutex
	probeIP   string
)

// Prepare resolves the probe hostname once, BEFORE any tunnel is up. The
// resolved IP is cached and used by all subsequent Probe() calls. Safe to
// call multiple times — only the first resolution matters.
func Prepare(ctx context.Context) {
	probeIPMu.Lock()
	defer probeIPMu.Unlock()
	if probeIP != "" {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(pctx, "ip4", probeHost)
	if err == nil && len(addrs) > 0 {
		probeIP = addrs[0].String()
		return
	}
	probeIP = fallbackProbeIP
}

// Result captures one probe.
type Result struct {
	Mbps      float64
	LatencyMS int64
	BytesRead int64
}

// IsUsable returns true if throughput is good enough for actual browsing.
func (r *Result) IsUsable() bool { return r != nil && r.Mbps >= MinUsableMbps }

// Probe sends a real HTTP request through the OS routing (i.e. our tunnel
// if one is up) and measures the throughput. Returns an error only on
// network failures; "too slow" is reflected in Result.Mbps, which the
// caller compares to MinUsableMbps.
func Probe(ctx context.Context) (*Result, error) {
	// Let freshly-installed routes propagate before measuring.
	select {
	case <-time.After(defaultSettleDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	ip := currentProbeIP()
	url := fmt.Sprintf("http://%s/__down?bytes=%d", ip, defaultPayloadBytes)

	pctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Cloudflare's edge needs the Host header to route to the right backend
	// even when we dial the IP directly.
	req.Host = probeHost
	req.Header.Set("Cache-Control", "no-cache")

	// Fresh client so connection state doesn't leak between probes (which
	// would otherwise inflate later measurements).
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 6 * time.Second,
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe got HTTP %d", resp.StatusCode)
	}

	n, copyErr := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	if copyErr != nil {
		return nil, fmt.Errorf("probe body read failed: %w", copyErr)
	}
	if n < int64(defaultPayloadBytes/4) {
		return nil, fmt.Errorf("probe truncated: only got %d bytes", n)
	}

	mbps := (float64(n) * 8) / elapsed.Seconds() / 1_000_000
	return &Result{
		Mbps:      mbps,
		LatencyMS: elapsed.Milliseconds(),
		BytesRead: n,
	}, nil
}

func currentProbeIP() string {
	probeIPMu.Lock()
	defer probeIPMu.Unlock()
	if probeIP == "" {
		return fallbackProbeIP
	}
	return probeIP
}
