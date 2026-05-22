// Package speedtest measures real throughput through whatever tunnel is
// currently up. We download a known-size payload from Cloudflare's speed
// endpoint and time it; the result reveals whether the user can actually
// browse, not just whether a TCP connection succeeded.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Defaults — tuned for "can the user load a webpage at all?" rather than for
// raw speedtest accuracy. 200 KB is large enough to see real throughput,
// small enough to finish quickly even on slow servers.
const (
	defaultPayloadBytes = 200_000
	defaultTimeout      = 10 * time.Second
	defaultSettleDelay  = 600 * time.Millisecond
	// MinUsableMbps is our "is this server actually browsable?" threshold.
	// 0.5 Mbps ≈ 60 KB/s — slow but functional for text-mostly browsing.
	MinUsableMbps = 0.5
)

// Result captures one probe.
type Result struct {
	Mbps        float64
	LatencyMS   int64
	BytesRead   int64
	Endpoint    string
}

// Probe sends a real HTTP request through whatever the OS routes things
// through right now (which is our tunnel once sing-box / openvpn is up).
// Returns the measured throughput. Returns an error if the request fails or
// the connection is closed mid-transfer.
//
// Cancel ctx to abort early — useful when the caller wants to kill the
// engine and try a different server.
func Probe(ctx context.Context) (*Result, error) {
	// Brief settle delay so freshly-installed routes propagate before we hit
	// the network. Skipping this trips on Windows where the TUN adapter's
	// default-route metric takes a moment to outrank the physical adapter.
	select {
	case <-time.After(defaultSettleDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	pctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	url := fmt.Sprintf("http://speed.cloudflare.com/__down?bytes=%d", defaultPayloadBytes)
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Disable HTTP cache + keep-alive reuse — we want a clean measurement.
	req.Header.Set("Cache-Control", "no-cache")

	// Use a fresh client each call so connection state doesn't leak between
	// probes (which would otherwise inflate later measurements).
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe got HTTP %d", resp.StatusCode)
	}

	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if n < int64(defaultPayloadBytes/4) {
		return nil, fmt.Errorf("only read %d bytes (expected ~%d)", n, defaultPayloadBytes)
	}

	mbps := (float64(n) * 8) / elapsed.Seconds() / 1_000_000
	return &Result{
		Mbps:      mbps,
		LatencyMS: elapsed.Milliseconds(),
		BytesRead: n,
		Endpoint:  url,
	}, nil
}

// IsUsable returns true if the result is good enough to actually browse with.
func (r *Result) IsUsable() bool { return r != nil && r.Mbps >= MinUsableMbps }
