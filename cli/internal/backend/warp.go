package backend

// Cloudflare WARP — https://1.1.1.1
//
// WARP is Cloudflare's free, anonymous WireGuard-based tunnel. We register
// once anonymously against api.cloudflareclient.com, cache the resulting
// credentials to disk, and surface a single virtual server in the picker
// (the exit is Cloudflare's anycast, not a country we can pick).
//
// Why it's a single virtual entry: on the free tier the exit IP is whatever
// Cloudflare PoP is closest to the user. There's no per-country selection
// without a paid subscription, so promising "100 new countries" would be a
// lie. We name the entry "Anywhere — Cloudflare WARP" so users know.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/KatrielMoses/tun0access/internal/proxy"
	"golang.org/x/crypto/curve25519"
)

const (
	warpAPIBase    = "https://api.cloudflareclient.com"
	warpAPIVersion = "v0a1922"
	warpUserAgent  = "okhttp/3.12.1"
	warpClientVer  = "a-6.3-1922"

	// WARP's well-known anycast endpoint — used directly in the WireGuard
	// peer regardless of the IP the registration response also lists.
	warpPeerHost = "engage.cloudflareclient.com"
	warpPeerPort = 2408

	// Cached registration is reused indefinitely; Cloudflare doesn't expire
	// anonymous WARP devices unless the user explicitly deletes them. We do
	// add a sanity ceiling so a corrupted cache eventually re-registers.
	warpCacheMaxAge = 90 * 24 * time.Hour

	// Virtual "country" code used so the picker can render a unique entry.
	// flag-rendering in ui/picker.go special-cases this code to skip the
	// regional-indicator letter trick.
	warpCountryCode = "XX"
	warpCountryName = "Anywhere — Cloudflare WARP"
)

// WARP is the Cloudflare WARP backend.
type WARP struct {
	HTTP *http.Client

	mu       sync.Mutex
	cache    []Server
	cachedAt time.Time
}

func NewWARP() *WARP {
	return &WARP{
		HTTP: &http.Client{
			// Cloudflare's API rejects anything other than TLS 1.2 with code
			// 403 / cf-ray "1020" — match the 1.1.1.1 app's stack exactly.
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS12,
				},
				ForceAttemptHTTP2: false,
			},
			Timeout: 30 * time.Second,
		},
	}
}

func (w *WARP) Name() string { return "warp" }

func (w *WARP) Fetch(ctx context.Context) ([]Server, error) {
	w.mu.Lock()
	if time.Since(w.cachedAt) < 6*time.Hour && len(w.cache) > 0 {
		out := w.cache
		w.mu.Unlock()
		return out, nil
	}
	w.mu.Unlock()

	reg, err := w.ensureRegistration(ctx)
	if err != nil {
		return nil, fmt.Errorf("warp: %w", err)
	}

	out := proxy.Outbound{
		Protocol:      "wireguard",
		Tag:           "Cloudflare WARP",
		Server:        warpPeerHost,
		ServerPort:    warpPeerPort,
		PrivateKey:    reg.PrivateKey,
		PeerPublicKey: reg.PeerPublicKey,
		PeerEndpoint:  warpPeerHost,
		PeerPort:      warpPeerPort,
		PeerReserved:  reg.Reserved,
		LocalAddress:  []string{reg.IPv4 + "/32", reg.IPv6 + "/128"},
		MTU:           1280,
	}
	cfgJSON, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	servers := []Server{{
		ID:           "warp:anycast",
		Backend:      "warp",
		CountryLong:  warpCountryName,
		CountryShort: warpCountryCode,
		Host:         warpPeerHost,
		Score:        75, // higher than ss-aggregator baseline; lower than fast SS hits
		Protocol:     "wireguard",
		Config:       cfgJSON,
	}}

	w.mu.Lock()
	w.cache = servers
	w.cachedAt = time.Now()
	w.mu.Unlock()
	return servers, nil
}

// ── registration + disk cache ───────────────────────────────────────────

// warpRegistration is the subset of the registration response we cache.
type warpRegistration struct {
	RegisteredAt  time.Time `json:"registered_at"`
	DeviceID      string    `json:"device_id"`
	Token         string    `json:"token"`
	License       string    `json:"license"`
	PrivateKey    string    `json:"private_key"`
	PeerPublicKey string    `json:"peer_public_key"`
	IPv4          string    `json:"ipv4"`
	IPv6          string    `json:"ipv6"`
	Reserved      []byte    `json:"reserved"`
}

func (w *WARP) ensureRegistration(ctx context.Context) (*warpRegistration, error) {
	if reg, ok := loadWarpCache(); ok && time.Since(reg.RegisteredAt) < warpCacheMaxAge {
		return reg, nil
	}
	reg, err := w.register(ctx)
	if err != nil {
		return nil, err
	}
	saveWarpCache(reg)
	return reg, nil
}

// Cloudflare register payload + response (only the fields we need).
type warpRegRequest struct {
	FcmToken  string `json:"fcm_token"`
	InstallID string `json:"install_id"`
	Key       string `json:"key"`
	Locale    string `json:"locale"`
	Model     string `json:"model"`
	Tos       string `json:"tos"`
	Type      string `json:"type"`
}

type warpRegResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func (w *WARP) register(ctx context.Context) (*warpRegistration, error) {
	priv, pub, err := generateCurve25519Pair()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	body, _ := json.Marshal(warpRegRequest{
		Key:    pub,
		Locale: "en_US",
		Model:  "PC",
		Tos:    time.Now().UTC().Format(time.RFC3339Nano),
		Type:   "Android",
	})

	url := fmt.Sprintf("%s/%s/reg", warpAPIBase, warpAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", warpUserAgent)
	req.Header.Set("CF-Client-Version", warpClientVer)

	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("register HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	respData, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var r warpRegResponse
	if err := json.Unmarshal(respData, &r); err != nil {
		return nil, fmt.Errorf("decode register: %w", err)
	}
	if len(r.Config.Peers) == 0 {
		return nil, fmt.Errorf("register: no peers in response")
	}
	reserved, err := base64.StdEncoding.DecodeString(r.Config.ClientID)
	if err != nil {
		return nil, fmt.Errorf("decode client_id: %w", err)
	}

	return &warpRegistration{
		RegisteredAt:  time.Now(),
		DeviceID:      r.ID,
		Token:         r.Token,
		License:       r.Account.License,
		PrivateKey:    priv,
		PeerPublicKey: r.Config.Peers[0].PublicKey,
		IPv4:          r.Config.Interface.Addresses.V4,
		IPv6:          r.Config.Interface.Addresses.V6,
		Reserved:      reserved,
	}, nil
}

// ── curve25519 key generation (matches wgcf / the 1.1.1.1 app) ──────────

func generateCurve25519Pair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	// Curve25519 private key clamping per RFC 7748.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}

// ── disk cache ──────────────────────────────────────────────────────────

func warpCacheFile() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "tun0access", "cache", "warp.json")
		}
	case "darwin":
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, "Library", "Caches", "tun0access", "warp.json")
		}
	default:
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, ".cache", "tun0access", "warp.json")
		}
	}
	return ""
}

func loadWarpCache() (*warpRegistration, bool) {
	path := warpCacheFile()
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var reg warpRegistration
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, false
	}
	if reg.PrivateKey == "" || reg.PeerPublicKey == "" || reg.IPv4 == "" {
		return nil, false
	}
	return &reg, true
}

func saveWarpCache(reg *warpRegistration) {
	path := warpCacheFile()
	if path == "" {
		return
	}
	data, err := json.Marshal(reg)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, data, 0o600)
}

func init() { Register(NewWARP()) }
