package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Run builds a sing-box config from the parsed Outbound, writes it to a temp
// file, and runs sing-box as a child process. The TUN inbound creates a
// system network interface and auto_route forwards all traffic through the
// outbound — the user is effectively VPN'd through the chosen server.
//
// Requires admin/root because creating a TUN device is privileged. On
// Linux/macOS we re-exec via sudo if not already root.
func Run(ctx context.Context, singBoxBin string, out *Outbound) error {
	cfg, err := buildConfig(out)
	if err != nil {
		return fmt.Errorf("build sing-box config: %w", err)
	}

	dir, err := os.MkdirTemp("", "tun0access-sb-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}

	args := []string{"run", "-c", cfgPath}
	name := singBoxBin
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if _, lerr := exec.LookPath("sudo"); lerr == nil {
			args = append([]string{"-E", singBoxBin}, args...)
			name = "sudo"
		}
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sing-box exited: %w", err)
	}
	return nil
}

// singBoxConfig is a partial sing-box v1.x JSON config — only the fields we
// actually populate.
type singBoxConfig struct {
	Log      map[string]any `json:"log"`
	DNS      map[string]any `json:"dns"`
	Inbounds []any          `json:"inbounds"`
	Outbounds []any         `json:"outbounds"`
	Route    map[string]any `json:"route"`
}

// buildConfig translates a parsed Outbound into a runnable sing-box config.
func buildConfig(out *Outbound) ([]byte, error) {
	outbound, err := outboundConfig(out)
	if err != nil {
		return nil, err
	}

	cfg := singBoxConfig{
		Log: map[string]any{"level": "warn", "timestamp": true},
		DNS: map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "address": "1.1.1.1", "detour": "proxy"},
				map[string]any{"tag": "local", "address": "local", "detour": "direct"},
			},
			"rules": []any{
				map[string]any{"clash_mode": "direct", "server": "local"},
				map[string]any{"clash_mode": "global", "server": "remote"},
			},
			"final": "remote",
		},
		Inbounds: []any{
			map[string]any{
				"type":            "tun",
				"tag":             "tun-in",
				"address":         []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"auto_route":      true,
				"strict_route":    true,
				"stack":           "mixed",
				"sniff":           true,
			},
		},
		Outbounds: []any{
			outbound,
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		Route: map[string]any{
			"auto_detect_interface": true,
			"final":                 "proxy",
			"rules": []any{
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// outboundConfig produces the protocol-specific outbound block. The tag is
// always "proxy" so the routing rules don't have to know the protocol.
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
			// trojan mandates TLS
			base["tls"] = map[string]any{"enabled": true, "insecure": true}
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", o.Protocol)
	}
	return base, nil
}

// buildTransport returns the sing-box transport block, or nil for plain TCP.
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
