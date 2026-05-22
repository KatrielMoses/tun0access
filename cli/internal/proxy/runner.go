package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/KatrielMoses/tun0access/internal/runtools"
)

// RunOptions configures a sing-box session.
type RunOptions struct {
	Binary  string
	Out     *Outbound
	Verbose bool
	OnReady func()
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

	cmd := exec.CommandContext(ctx, name, args...)
	return runtools.Run(ctx, runtools.Options{
		Cmd:     cmd,
		Verbose: opts.Verbose,
		OnReady: opts.OnReady,
		UserOut: os.Stderr,
	})
}

// singBoxConfig is a partial sing-box v1.x JSON config — only the fields we
// actually populate.
type singBoxConfig struct {
	Log       map[string]any `json:"log"`
	DNS       map[string]any `json:"dns"`
	Inbounds  []any          `json:"inbounds"`
	Outbounds []any          `json:"outbounds"`
	Route     map[string]any `json:"route"`
}

func buildConfig(out *Outbound) ([]byte, error) {
	outbound, err := outboundConfig(out)
	if err != nil {
		return nil, err
	}

	cfg := singBoxConfig{
		Log: map[string]any{"level": "warn", "timestamp": true},
		// sing-box 1.12+ DNS format: type/server fields instead of legacy address.
		DNS: map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "type": "udp", "server": "1.1.1.1", "detour": "proxy"},
				map[string]any{"tag": "local", "type": "local"},
			},
			"final": "remote",
		},
		// sing-box 1.11+ removed the inbound `sniff` field; sniffing is now a
		// route rule action. Same for protocol-sniffing of DNS — moved to a
		// `hijack-dns` action.
		Inbounds: []any{
			map[string]any{
				"type":         "tun",
				"tag":          "tun-in",
				"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
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
			"auto_detect_interface": true,
			"final":                 "proxy",
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
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
