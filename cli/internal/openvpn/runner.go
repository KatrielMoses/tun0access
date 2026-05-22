package openvpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/KatrielMoses/tun0access/internal/runtools"
)

// Credentials holds auth details for backends that need them (e.g. VPNBook).
type Credentials struct {
	Username string
	Password string
}

// RunOptions bundles everything Run needs to start an openvpn session.
type RunOptions struct {
	Binary      string
	Config      []byte
	Credentials *Credentials
	Verbose     bool
	OnReady     func() // called once when "Initialization Sequence Completed" is seen
}

// Run executes openvpn with the provided options. Returns the captured
// subprocess output (tail-limited) and the exit error. Callers diagnose the
// output with the diagnose package on failure.
func Run(ctx context.Context, opts RunOptions) (string, error) {
	if opts.Binary == "" {
		return "", fmt.Errorf("openvpn binary path is empty")
	}

	dir, err := os.MkdirTemp("", "tun0access-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	cfgPath := filepath.Join(dir, "server.ovpn")
	if err := os.WriteFile(cfgPath, opts.Config, 0o600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	args := []string{
		"--config", cfgPath,
		"--verb", "3",
		// Cover legacy VPN Gate servers that still advertise AES-128-CBC.
		"--data-ciphers", "AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:CHACHA20-POLY1305",
	}

	if opts.Credentials != nil {
		authPath := filepath.Join(dir, "auth.txt")
		authContent := opts.Credentials.Username + "\n" + opts.Credentials.Password + "\n"
		if err := os.WriteFile(authPath, []byte(authContent), 0o600); err != nil {
			return "", fmt.Errorf("write auth file: %w", err)
		}
		args = append(args, "--auth-user-pass", authPath)
	}

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
