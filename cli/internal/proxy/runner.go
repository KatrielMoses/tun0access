package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/KatrielMoses/tun0access/internal/runtools"
)

// RunOptions configures a sing-box session.
type RunOptions struct {
	Binary        string
	Out           *Outbound
	Verbose       bool
	OnReady       func()
	ReadyDeadline time.Duration
}

// Run builds a sing-box config from the parsed Outbound, writes it to a temp
// file, and runs sing-box as a child process. Returns the captured output
// and the subprocess exit error. Creating the TUN device requires admin/root.
func Run(ctx context.Context, opts RunOptions) (string, error) {
	if opts.Binary == "" {
		return "", fmt.Errorf("sing-box binary path is empty")
	}
	if opts.Out == nil {
		return "", fmt.Errorf("nil outbound")
	}

	cfg, err := buildConfig(opts.Out)
	if err != nil {
		return "", fmt.Errorf("build sing-box config: %w", err)
	}

	dir, err := os.MkdirTemp("", "tun0access-sb-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return "", err
	}

	args := []string{"run", "-c", cfgPath}
	name := opts.Binary
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if _, lerr := exec.LookPath("sudo"); lerr == nil {
			args = append([]string{"-E", opts.Binary}, args...)
			name = "sudo"
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(runCtx, name, args...)
	return runtools.Run(ctx, runtools.Options{
		Cmd:              cmd,
		Verbose:          opts.Verbose,
		OnReady:          opts.OnReady,
		UserOut:           os.Stderr,
		ReadyDeadline:    opts.ReadyDeadline,
		CancelOnDeadline: cancel,
	})
}

// singBoxConfig is a partial sing-box v1.x JSON config — only the fields we
// actually populate. `endpoints` is a top-level array introduced in 1.13
// for protocols whose dialer also creates a network interface (currently
// only WireGuard).
type singBoxConfig struct {
	Log       map[string]any `json:"log"`
	DNS       map[string]any `json:"dns"`
	Inbounds  []any          `json:"inbounds"`
	Endpoints []any          `json:"endpoints,omitempty"`
	Outbounds []any          `json:"outbounds"`
	Route     map[string]any `json:"route"`
}

// BuildConfigForValidate is exported only so the `tun0access validate`
// command can run sing-box check against the same config the runner would
// generate. Not part of the public API; do not call from outside cmd/.
func BuildConfigForValidate(out *Outbound) ([]byte, error) { return buildConfig(out) }

func buildConfig(out *Outbound) ([]byte, error) {
	// WireGuard lives in `endpoints[]`, not `outbounds[]`, in sing-box 1.13+.
	// We build it differently and keep `outbounds[]` minimal — just `direct`
	// so private-IP routes still work.
	if out.Protocol == "wireguard" {
		return buildWireGuardConfig(out)
	}

	outbound, err := outboundConfig(out)
	if err != nil {
		return nil, err
	}

	cfg := singBoxConfig{
		// info-level is required: "sing-box started" — our success marker — is
		// logged at INFO. At warn the line is suppressed and we never know the
		// tunnel is up. Raw output is hidden from the user unless --verbose,
		// so the chattier log doesn't affect UX.
		Log: map[string]any{"level": "info", "timestamp": true},
		// DNS uses `local` (OS resolver) so queries do NOT traverse the proxy.
		// Free SS/Trojan servers are slow → routing DNS through them produced
		// 30s+ resolution times in practice and made "Connected ✓ but can't
		// browse" the default user experience.
		//
		// `strategy: "ipv4_only"` stops the OS from offering AAAA records to
		// apps. Without it, browsers Happy-Eyeball IPv6 first; free trojan
		// servers almost never carry IPv6, so each request stalls 300-1000ms
		// waiting for the IPv6 attempt to fail before falling back to v4.
		DNS: map[string]any{
			"servers": []any{
				map[string]any{"tag": "local", "type": "local"},
			},
			"strategy": "ipv4_only",
			"final":    "local",
		},
		// sing-box 1.11+ removed the inbound `sniff` field; sniffing is now a
		// route rule action. We also keep an IPv6 address on the TUN so any
		// stray IPv6 traffic from apps still enters sing-box (where we reject
		// it explicitly below) instead of leaking via the physical interface.
		//
		// mtu: 1380 leaves headroom for trojan/TLS encapsulation overhead;
		// otherwise full-MTU packets get fragmented or silently dropped,
		// which kills TLS handshakes long before throughput tests notice.
		Inbounds: []any{
			map[string]any{
				"type":         "tun",
				"tag":          "tun-in",
				"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"mtu":          1380,
				"auto_route":   true,
				"strict_route": true,
				"stack":        "mixed",
			},
		},
		Outbounds: []any{
			outbound,
			map[string]any{"type": "direct", "tag": "direct"},
		},
		Route: map[string]any{
			"default_domain_resolver": "local",
			"auto_detect_interface":   true,
			"final":                   "proxy",
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				// Reject IPv6 fast so Happy-Eyeballs apps fall back to v4 in
				// <100ms instead of waiting for a tunnel-side timeout.
				map[string]any{"ip_version": 6, "action": "reject"},
				map[string]any{"ip_is_private": true, "action": "route", "outbound": "direct"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// buildWireGuardConfig generates a sing-box config where the proxy lives in
// `endpoints[]` (the new sing-box 1.13 home for WireGuard) and DNS / route
// point at that endpoint's tag. Used by the WARP backend.
func buildWireGuardConfig(o *Outbound) ([]byte, error) {
	if o.PrivateKey == "" || o.PeerPublicKey == "" || o.PeerEndpoint == "" || o.PeerPort == 0 {
		return nil, fmt.Errorf("wireguard: missing key/peer info")
	}
	mtu := o.MTU
	if mtu == 0 {
		mtu = 1280
	}
	peer := map[string]any{
		"address":                       o.PeerEndpoint,
		"port":                          o.PeerPort,
		"public_key":                    o.PeerPublicKey,
		"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
		"persistent_keepalive_interval": 25,
	}
	if len(o.PeerReserved) > 0 {
		// sing-box wants []uint8 as a JSON array of decimal ints; matches []byte.
		peer["reserved"] = o.PeerReserved
	}

	const tag = "proxy"
	cfg := singBoxConfig{
		Log: map[string]any{"level": "info", "timestamp": true},
		DNS: map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "type": "udp", "server": "1.1.1.1", "detour": tag},
				map[string]any{"tag": "local", "type": "local"},
			},
			"final": "remote",
		},
		Inbounds: []any{
			map[string]any{
				"type":         "tun",
				"tag":          "tun-in",
				"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"mtu":          1380,
				"auto_route":   true,
				"strict_route": true,
				"stack":        "mixed",
			},
		},
		Endpoints: []any{
			map[string]any{
				"type":        "wireguard",
				"tag":         tag,
				"system":      false,
				"mtu":         mtu,
				"address":     o.LocalAddress,
				"private_key": o.PrivateKey,
				"peers":       []any{peer},
			},
		},
		Outbounds: []any{
			map[string]any{"type": "direct", "tag": "direct"},
		},
		Route: map[string]any{
			"auto_detect_interface":   true,
			"final":                   tag,
			"default_domain_resolver": "local",
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_version": 6, "action": "reject"},
				map[string]any{"ip_is_private": true, "action": "route", "outbound": "direct"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func outboundConfig(o *Outbound) (map[string]any, error) {
	base := map[string]any{
		"tag":         "proxy",
		"server":      o.Server,
		"server_port": o.ServerPort,
	}

	transport := buildTransport(o)
	tls := buildTLS(o)

	switch o.Protocol {
	case "shadowsocks":
		base["type"] = "shadowsocks"
		base["method"] = o.Method
		base["password"] = o.Password
	case "vmess":
		base["type"] = "vmess"
		base["uuid"] = o.UUID
		base["alter_id"] = o.AlterID
		base["security"] = o.Security
		if transport != nil {
			base["transport"] = transport
		}
		if tls != nil {
			base["tls"] = tls
		}
	case "vless":
		base["type"] = "vless"
		base["uuid"] = o.UUID
		if o.Flow != "" {
			base["flow"] = o.Flow
		}
		if transport != nil {
			base["transport"] = transport
		}
		if tls != nil {
			base["tls"] = tls
		}
	case "trojan":
		base["type"] = "trojan"
		base["password"] = o.Password
		if transport != nil {
			base["transport"] = transport
		}
		if tls != nil {
			base["tls"] = tls
		} else {
			base["tls"] = map[string]any{"enabled": true, "insecure": true}
		}
	case "tuic":
		base["type"] = "tuic"
		base["uuid"] = o.UUID
		base["password"] = o.Password
		base["congestion_control"] = o.CongestionControl
		base["udp_relay_mode"] = o.UDPRelayMode
		base["tls"] = tlsOrDefault(o, []string{"h3"})
	case "hysteria2":
		base["type"] = "hysteria2"
		base["password"] = o.Password
		if o.ObfsType != "" {
			base["obfs"] = map[string]any{"type": o.ObfsType, "password": o.ObfsPassword}
		}
		base["tls"] = tlsOrDefault(o, []string{"h3"})
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", o.Protocol)
	}
	return base, nil
}

func buildTransport(o *Outbound) map[string]any {
	switch o.Network {
	case "ws":
		t := map[string]any{"type": "ws"}
		if o.WSPath != "" {
			t["path"] = o.WSPath
		}
		if o.WSHost != "" {
			t["headers"] = map[string]any{"Host": o.WSHost}
		}
		return t
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": o.GRPCServiceName}
	case "http", "h2":
		t := map[string]any{"type": "http"}
		if o.WSHost != "" {
			t["host"] = []string{o.WSHost}
		}
		if o.WSPath != "" {
			t["path"] = o.WSPath
		}
		return t
	default:
		return nil
	}
}

// tlsOrDefault returns buildTLS(o) when the URI advertised TLS, or a
// permissive default TLS block with the given ALPN. Used by protocols where
// TLS is mandatory (TUIC, Hysteria2 — both ride QUIC).
func tlsOrDefault(o *Outbound, defaultALPN []string) map[string]any {
	if t := buildTLS(o); t != nil {
		if _, hasALPN := t["alpn"]; !hasALPN && len(defaultALPN) > 0 {
			t["alpn"] = defaultALPN
		}
		return t
	}
	t := map[string]any{"enabled": true, "insecure": o.SkipCertVerify}
	if o.SNI != "" {
		t["server_name"] = o.SNI
	}
	if len(defaultALPN) > 0 {
		t["alpn"] = defaultALPN
	}
	return t
}

func buildTLS(o *Outbound) map[string]any {
	if !o.TLS {
		return nil
	}
	tls := map[string]any{"enabled": true, "insecure": o.SkipCertVerify}
	if o.SNI != "" {
		tls["server_name"] = o.SNI
	} else if o.WSHost != "" {
		tls["server_name"] = o.WSHost
	}
	if len(o.ALPN) > 0 {
		tls["alpn"] = o.ALPN
	}
	return tls
}
