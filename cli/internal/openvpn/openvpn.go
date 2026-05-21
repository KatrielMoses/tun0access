// Package openvpn locates the openvpn binary on the host, offers to install
// it via the platform package manager when it is missing, and runs it
// against a server config provided by a backend.
package openvpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ErrNotInstalled is returned when openvpn cannot be located on PATH and we
// can't (or won't) install it for the caller.
var ErrNotInstalled = errors.New("openvpn is not installed")

// Locate returns the absolute path to an openvpn binary, or "" if none is
// found. It searches PATH plus a few well-known install locations on Windows
// and macOS where the binary often is not on PATH by default.
func Locate() string {
	if p, err := exec.LookPath("openvpn"); err == nil {
		return p
	}
	for _, p := range wellKnownPaths() {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func wellKnownPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Program Files\OpenVPN\bin\openvpn.exe`,
			`C:\Program Files (x86)\OpenVPN\bin\openvpn.exe`,
		}
	case "darwin":
		return []string{
			"/opt/homebrew/sbin/openvpn",
			"/usr/local/sbin/openvpn",
			"/opt/homebrew/opt/openvpn/sbin/openvpn",
			"/usr/local/opt/openvpn/sbin/openvpn",
		}
	default:
		return []string{"/usr/sbin/openvpn", "/usr/local/sbin/openvpn"}
	}
}

// EnsureInstalled returns the path to openvpn, installing it via the platform
// package manager if necessary and if autoInstall is true. The install step
// is interactive (it will print progress and may prompt for elevation), so
// callers should only set autoInstall=true from foreground commands.
func EnsureInstalled(ctx context.Context, autoInstall bool) (string, error) {
	if p := Locate(); p != "" {
		return p, nil
	}
	if !autoInstall {
		return "", ErrNotInstalled
	}
	if err := install(ctx); err != nil {
		return "", fmt.Errorf("auto-install failed: %w\n\n%s", err, manualInstructions())
	}
	if p := Locate(); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("openvpn still not found after install\n\n%s", manualInstructions())
}

func install(ctx context.Context) error {
	switch runtime.GOOS {
	case "windows":
		return runStreaming(ctx, "winget", "install", "--id", "OpenVPNTechnologies.OpenVPN", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements")
	case "darwin":
		if _, err := exec.LookPath("brew"); err != nil {
			return errors.New("Homebrew not found — install brew from https://brew.sh and re-run")
		}
		return runStreaming(ctx, "brew", "install", "openvpn")
	case "linux":
		return installLinux(ctx)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func installLinux(ctx context.Context) error {
	// Try package managers in order of popularity.
	candidates := [][]string{
		{"apt-get", "install", "-y", "openvpn"},
		{"dnf", "install", "-y", "openvpn"},
		{"yum", "install", "-y", "openvpn"},
		{"pacman", "-S", "--noconfirm", "openvpn"},
		{"zypper", "install", "-y", "openvpn"},
		{"apk", "add", "openvpn"},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		args := c
		if os.Geteuid() != 0 {
			if _, err := exec.LookPath("sudo"); err == nil {
				args = append([]string{"sudo"}, c...)
			} else {
				return fmt.Errorf("found %s but not root and sudo unavailable", c[0])
			}
		}
		return runStreaming(ctx, args[0], args[1:]...)
	}
	return errors.New("no supported package manager found (apt/dnf/yum/pacman/zypper/apk)")
}

func runStreaming(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func manualInstructions() string {
	switch runtime.GOOS {
	case "windows":
		return "Install OpenVPN manually:\n  winget install OpenVPNTechnologies.OpenVPN\n  (or download from https://openvpn.net/community-downloads/)"
	case "darwin":
		return "Install OpenVPN manually:\n  brew install openvpn"
	case "linux":
		return "Install OpenVPN with your distro's package manager, e.g.:\n  sudo apt install openvpn       (Debian/Ubuntu)\n  sudo dnf install openvpn       (Fedora/RHEL)\n  sudo pacman -S openvpn          (Arch)"
	default:
		return "Install OpenVPN for your platform from https://openvpn.net/community-downloads/"
	}
}

// Verify returns an error if the located binary cannot run --version. This
// is a cheap sanity check before we hand it a server config.
func Verify(ctx context.Context, path string) error {
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		// openvpn --version exits non-zero on some builds; accept that as long
		// as the output contains the expected banner.
		if !strings.Contains(string(out), "OpenVPN") {
			return fmt.Errorf("openvpn --version failed: %v\n%s", err, out)
		}
	}
	return nil
}
