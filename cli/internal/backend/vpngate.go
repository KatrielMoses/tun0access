package backend

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vpnGateAPIURL = "https://www.vpngate.net/api/iphone/"
	// VPN Gate is community-run and rate-sensitive; cache aggressively.
	vpnGateCacheTTL = 10 * time.Minute
)

// VPNGate is the University of Tsukuba's free public VPN relay pool. The
// /api/iphone/ endpoint returns a CSV with one row per server and the .ovpn
// config inline as base64 in the last column.
type VPNGate struct {
	HTTP *http.Client

	mu       sync.Mutex
	cache    []Server
	cachedAt time.Time
}

func NewVPNGate() *VPNGate {
	return &VPNGate{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (v *VPNGate) Name() string { return "vpngate" }

func (v *VPNGate) Fetch(ctx context.Context) ([]Server, error) {
	v.mu.Lock()
	if time.Since(v.cachedAt) < vpnGateCacheTTL && len(v.cache) > 0 {
		out := v.cache
		v.mu.Unlock()
		return out, nil
	}
	v.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vpnGateAPIURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", vpnGateAPIURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vpngate API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	servers, err := parseVPNGateCSV(body)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	v.cache = servers
	v.cachedAt = time.Now()
	v.mu.Unlock()
	return servers, nil
}

// parseVPNGateCSV decodes the VPN Gate CSV response. The body starts with
// "*vpn_servers" and ends with "*", with a "#HostName,IP,..." header line
// between them. Column order is documented at vpngate.net.
func parseVPNGateCSV(body []byte) ([]Server, error) {
	text := string(body)
	start := strings.Index(text, "#HostName,")
	if start < 0 {
		return nil, fmt.Errorf("vpngate: unexpected response (no header row)")
	}
	end := strings.LastIndex(text, "*")
	if end <= start {
		end = len(text)
	}
	clean := strings.TrimPrefix(text[start:end], "#")

	r := csv.NewReader(strings.NewReader(clean))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("vpngate: parse CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("vpngate: no server rows")
	}

	header := rows[0]
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}

	get := func(row []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}

	var out []Server
	for _, row := range rows[1:] {
		if len(row) < len(header) {
			continue
		}
		cfgB64 := get(row, "OpenVPN_ConfigData_Base64")
		if cfgB64 == "" {
			continue
		}
		cfg, err := base64.StdEncoding.DecodeString(cfgB64)
		if err != nil {
			continue
		}
		score, _ := strconv.ParseInt(get(row, "Score"), 10, 64)
		ping, _ := strconv.Atoi(get(row, "Ping"))
		speed, _ := strconv.ParseInt(get(row, "Speed"), 10, 64)

		host := get(row, "HostName")
		ip := get(row, "IP")
		id := host
		if id == "" {
			id = ip
		}

		out = append(out, Server{
			ID:           "vpngate:" + id,
			Backend:      "vpngate",
			CountryLong:  get(row, "CountryLong"),
			CountryShort: strings.ToUpper(get(row, "CountryShort")),
			Host:         ip,
			Score:        score,
			PingMS:       ping,
			SpeedBps:     speed,
			Protocol:     "openvpn",
			Config:       cfg,
		})
	}
	return out, nil
}

func init() { Register(NewVPNGate()) }
