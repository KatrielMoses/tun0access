package openvpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	Credentials *Credentials // nil → no --auth-user-pass flag
}

// Run executes openvpn with the provided options. The config (and optional
// credentials) are written to a private temp directory that is removed on
// exit. The function blocks until the child exits, streaming its output to
// the parent's stdout/stderr. Ctrl-C cancels ctx and terminates the process.
// On Linux/macOS the call re-execs via sudo if not already root.
func Run(ctx context.Context, opts RunOptions) error {
	if opts.Binary == "" {
		return fmt.Errorf("openvpn binary path is empty")
	}

	dir, err := os.MkdirTemp("", "tun0access-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	cfgPath := filepath.Join(dir, "server.ovpn")
	if err := os.WriteFile(cfgPath, opts.Config, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	args := []string{"--config", cfgPath, "--verb", "3"}

	if opts.Credentials != nil {
		authPath := filepath.Join(dir, "auth.txt")
		authContent := opts.Credentials.Username + "\n" + opts.Credentials.Password + "\n"
		if err := os.WriteFile(authPath, []byte(authContent), 0o600); err != nil {
			return fmt.Errorf("write auth file: %w", err)
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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openvpn exited: %w", err)
	}
	return nil
}
