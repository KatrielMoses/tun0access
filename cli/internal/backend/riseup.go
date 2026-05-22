package backend

// Riseup VPN — https://riseup.net/vpn
//
// Riseup is a non-profit collective running a completely free, no-account VPN
// via the LEAP protocol. Three public endpoints:
//
//   /3/config/eip-service.json  — server list + OpenVPN options
//   /ca.crt                     — provider CA certificate
//   /3/cert                     — anonymous per-session client cert + key (PEM)
//
// Country coverage: US (Seattle / Miami / NYC), Canada (Montreal),
// France (Paris), Netherlands (Amsterdam).
//
// Each call to /3/cert returns a fresh temporary key pair — no account or
// login required. We fetch one pair per Fetch() call and embed it into every
// server's inline config so the runner never needs to know about certs.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	riseupBase       = "https://api.black.riseup.net"
	riseupCacheTTL   = 6 * time.Hour // certs are valid for weeks; 6h is conservative
)

type riseupGateway struct {
	Capabilities struct {
		Transport []struct {
			Ports     []string `json:"ports"`
			Protocols []string `json:"protocols"`
			Type      string   `json:"type"`
		} `json:"transport"`
	} `json:"capabilities"`
	Host      string `json:"host"`
	IPAddress string `json:"ip_address"`
	Location  string `json:"location"`
}

type riseupConfig struct {
	Gateways  []riseupGateway    `json:"gateways"`
	Locations map[string]struct {
		CountryCode string `json:"country_code"`
		Name        string `json:"name"`
	} `json:"locations"`
	OpenVPNConfig map[string]any `json:"openvpn_configuration"`
}

// Riseup is the LEAP-based backend for Riseup VPN.
type Riseup struct {
	HTTP *http.Client

	mu       sync.Mutex
	cache    []Server
	cachedAt time.Time
}

func NewRiseup() *Riseup {
	return &Riseup{HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (r *Riseup) Name() string { return "riseup" }

func (r *Riseup) Fetch(ctx context.Context) ([]Server, error) {
	r.mu.Lock()
	if time.Since(r.cachedAt) < riseupCacheTTL && len(r.cache) > 0 {
		out := r.cache
		r.mu.Unlock()
		return out, nil
	}
	r.mu.Unlock()

	// Fetch all three pieces concurrently.
	type trio struct {
		eip    []byte
		ca     []byte
		client []byte
		err    error
	}
	ch := make(chan trio, 1)
	go func() {
		var t trio
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); t.eip, t.err = r.get(ctx, riseupBase+"/3/config/eip-service.json") }()
		go func() { defer wg.Done(); t.ca, t.err = r.get(ctx, riseupBase+"/ca.crt") }()
		go func() { defer wg.Done(); t.client, t.err = r.get(ctx, riseupBase+"/3/cert") }()
		wg.Wait()
		ch <- t
	}()
	t := <-ch
	if t.err != nil {
		return nil, fmt.Errorf("riseup: fetch failed: %w", t.err)
	}

	var cfg riseupConfig
	if err := json.Unmarshal(t.eip, &cfg); err != nil {
		return nil, fmt.Errorf("riseup: parse eip-service.json: %w", err)
	}
	if len(t.ca) == 0 || len(t.client) == 0 {
		return nil, fmt.Errorf("riseup: empty CA or client cert")
	}

	// Split client PEM into key and cert blocks.
	clientKey, clientCert, err := splitPEM(t.client)
	if err != nil {
		return nil, fmt.Errorf("riseup: split client PEM: %w", err)
	}

	var servers []Server
	for _, gw := range cfg.Gateways {
		loc, ok := cfg.Locations[gw.Location]
		if !ok {
			continue
		}
		// Find the best OpenVPN transport for this gateway.
		host, port, proto := bestTransport(gw)
		if host == "" {
			continue
		}
		cc := strings.ToUpper(loc.CountryCode)
		ovpn := buildRiseupConfig(gw.IPAddress, host, port, proto, t.ca, clientCert, clientKey, cfg.OpenVPNConfig)
		servers = append(servers, Server{
			ID:           "riseup:" + gw.Host,
			Backend:      "riseup",
			CountryLong:  riseupCountryName(cc),
			CountryShort: cc,
			City:         gw.Location,
			Host:         gw.IPAddress,
			Score:        50,
			Protocol:     "openvpn",
			Config:       ovpn,
		})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("riseup: no usable gateways in server list")
	}

	r.mu.Lock()
	r.cache = servers
	r.cachedAt = time.Now()
	r.mu.Unlock()
	return servers, nil
}

func (r *Riseup) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// bestTransport picks UDP port 1194 → UDP 53 → TCP 80 → TCP 443 in priority
// order, matching most firewall profiles.
func bestTransport(gw riseupGateway) (host, port, proto string) {
	type candidate struct{ proto, port string; priority int }
	var best candidate
	portPriority := map[string]int{"1194": 4, "53": 3, "80": 2, "443": 1}
	for _, tr := range gw.Capabilities.Transport {
		if tr.Type != "openvpn" {
			continue
		}
		for _, p := range tr.Protocols {
			for _, po := range tr.Ports {
				pri := portPriority[po]
				if p == "tcp" {
					pri-- // prefer UDP
				}
				if pri > best.priority {
					best = candidate{p, po, pri}
				}
			}
		}
	}
	if best.port == "" {
		return "", "", ""
	}
	return gw.IPAddress, best.port, best.proto
}

// splitPEM separates a PEM bundle that contains a PRIVATE KEY and a
// CERTIFICATE block (in any order).
func splitPEM(bundle []byte) (key, cert []byte, err error) {
	var keyBuf, certBuf bytes.Buffer
	s := string(bundle)
	blocks := strings.Split(s, "-----BEGIN ")
	for _, blk := range blocks {
		blk = strings.TrimSpace(blk)
		if blk == "" {
			continue
		}
		full := "-----BEGIN " + blk
		if strings.HasPrefix(blk, "RSA PRIVATE KEY") || strings.HasPrefix(blk, "PRIVATE KEY") || strings.HasPrefix(blk, "EC PRIVATE KEY") {
			keyBuf.WriteString(full + "\n")
		} else if strings.HasPrefix(blk, "CERTIFICATE") {
			certBuf.WriteString(full + "\n")
		}
	}
	if keyBuf.Len() == 0 || certBuf.Len() == 0 {
		return nil, nil, fmt.Errorf("could not find both KEY and CERTIFICATE in bundle")
	}
	return keyBuf.Bytes(), certBuf.Bytes(), nil
}

func buildRiseupConfig(ip, host, port, proto string, ca, cert, key []byte, opts map[string]any) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "client\ndev tun\nproto %s\n", proto)
	fmt.Fprintf(&b, "remote %s %s\n", ip, port)
	if host != ip {
		fmt.Fprintf(&b, "# verify-x509-name %s name\n", host)
	}
	b.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")

	// Translate openvpn_configuration fields.
	for k, v := range opts {
		switch s := v.(type) {
		case string:
			if s == "" {
				fmt.Fprintf(&b, "%s\n", k)
			} else {
				fmt.Fprintf(&b, "%s %s\n", k, s)
			}
		case bool:
			if s {
				fmt.Fprintf(&b, "%s\n", k)
			}
		case float64:
			if s != 0 {
				fmt.Fprintf(&b, "%s %.0f\n", k, s)
			}
		}
	}

	fmt.Fprintf(&b, "<ca>\n%s\n</ca>\n", strings.TrimSpace(string(ca)))
	fmt.Fprintf(&b, "<cert>\n%s\n</cert>\n", strings.TrimSpace(string(cert)))
	fmt.Fprintf(&b, "<key>\n%s\n</key>\n", strings.TrimSpace(string(key)))
	return []byte(b.String())
}

func riseupCountryName(cc string) string {
	names := map[string]string{
		"US": "United States",
		"CA": "Canada",
		"FR": "France",
		"NL": "Netherlands",
		"DE": "Germany",
		"GB": "United Kingdom",
		"SE": "Sweden",
	}
	if n, ok := names[cc]; ok {
		return n
	}
	return cc
}

func init() { Register(NewRiseup()) }
