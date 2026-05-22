// Package exitcheck tells us where the user's traffic is actually exiting
// once a tunnel is up. The "Finland" label on a server only describes where
// we *think* the proxy lives; many free configs are CDN-fronted or
// mislabelled in the source aggregator, so the real exit can be in another
// country. We ask ip-api.com from inside the tunnel to find out for real.
//
// Like the speed-probe, this is DNS-independent: we hardcode ip-api.com's
// anycast IP (208.95.112.1, stable for years) and send the request with
// `Host: ip-api.com` so the CDN routes correctly.
package exitcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	apiHost = "ip-api.com"
	// ip-api.com's anycast IP — pinned to avoid DNS through a possibly
	// slow / broken tunnel. Stable for years.
	apiIP = "208.95.112.1"

	defaultTimeout = 6 * time.Second
)

// Exit describes one observation of "where am I now?".
type Exit struct {
	IP          string
	CountryCode string // ISO-3166 alpha-2, uppercase
	CountryName string
	City        string
}

// Where queries ip-api.com from whatever the OS routes through (i.e. the
// active tunnel) and returns the public IP plus its geolocation.
func Where(ctx context.Context) (*Exit, error) {
	pctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	url := fmt.Sprintf("http://%s/json/?fields=status,country,countryCode,city,query", apiIP)
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = apiHost

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 4 * time.Second,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exit check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exit check HTTP %d", resp.StatusCode)
	}

	var r struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		Query       string `json:"query"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("exit check decode: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("ip-api status %q", r.Status)
	}
	return &Exit{
		IP:          r.Query,
		CountryCode: r.CountryCode,
		CountryName: r.Country,
		City:        r.City,
	}, nil
}
