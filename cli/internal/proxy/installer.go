package proxy

// sing-box auto-installer.
//
// Downloads the official SagerNet/sing-box release for the host OS/arch into
// a per-user cache directory and returns the absolute path. We bundle the
// binary in the cache rather than the project binary so updates are cheap
// (just re-download) and we don't bloat tun0access itself by 25-30 MB.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	singBoxVersion = "1.13.12"
	singBoxRepo    = "https://github.com/SagerNet/sing-box/releases/download"
)

// EnsureSingBox returns the absolute path to a working sing-box binary,
// downloading it on first use. Idempotent and concurrent-safe across runs
// (we use atomic rename, not a lock — last writer wins, which is harmless).
func EnsureSingBox(ctx context.Context) (string, error) {
	cacheDir, err := cacheDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	target := filepath.Join(cacheDir, "sing-box-"+singBoxVersion, binName)
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() && fi.Size() > 0 {
		return target, nil
	}

	url, archive, err := releaseURL()
	if err != nil {
		return "", err
	}

	fmt.Printf("• Downloading sing-box %s (one-time, ~12MB)…\n", singBoxVersion)
	body, err := download(ctx, url)
	if err != nil {
		return "", fmt.Errorf("download sing-box: %w", err)
	}

	extractDir := filepath.Join(cacheDir, "sing-box-"+singBoxVersion)
	if err := os.RemoveAll(extractDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", err
	}

	switch archive {
	case "zip":
		if err := unzipBinary(body, binName, extractDir); err != nil {
			return "", fmt.Errorf("unzip: %w", err)
		}
	case "tar.gz":
		if err := untarBinary(body, binName, extractDir); err != nil {
			return "", fmt.Errorf("untar: %w", err)
		}
	}

	if fi, err := os.Stat(target); err != nil || fi.Size() == 0 {
		return "", fmt.Errorf("sing-box binary missing after extraction at %s", target)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(target, 0o755)
	}
	return target, nil
}

func releaseURL() (url, archiveKind string, err error) {
	// sing-box release assets are named:
	//   sing-box-<version>-<os>-<arch>.<ext>
	// On Linux the asset has a libc suffix; we use the static musl build to
	// avoid glibc version drift.
	var assetOS, assetArch, ext, suffix string
	switch runtime.GOOS {
	case "windows":
		assetOS, ext = "windows", "zip"
	case "darwin":
		assetOS, ext = "darwin", "tar.gz"
	case "linux":
		assetOS, ext, suffix = "linux", "tar.gz", "-musl"
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64":
		assetArch = "amd64"
	case "arm64":
		assetArch = "arm64"
	case "arm":
		assetArch = "armv7"
	default:
		return "", "", fmt.Errorf("unsupported arch: %s", runtime.GOARCH)
	}
	asset := fmt.Sprintf("sing-box-%s-%s-%s%s.%s", singBoxVersion, assetOS, assetArch, suffix, ext)
	return fmt.Sprintf("%s/v%s/%s", singBoxRepo, singBoxVersion, asset), ext, nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// unzipBinary extracts every regular file from the archive into destDir
// (flattened — directory prefixes are dropped). The sing-box Windows archive
// ships a libcronet.dll next to the binary; some transports require it.
func unzipBinary(body []byte, name, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	found := false
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		dest := filepath.Join(destDir, filepath.Base(f.Name))
		if err := writeFile(dest, rc); err != nil {
			rc.Close()
			return err
		}
		rc.Close()
		if filepath.Base(f.Name) == name {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%s not found inside archive", name)
	}
	return nil
}

func untarBinary(body []byte, name, destDir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dest := filepath.Join(destDir, filepath.Base(hdr.Name))
		if err := writeFile(dest, tr); err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == name {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%s not found inside archive", name)
	}
	return nil
}

func writeFile(dest string, src io.Reader) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, src); err != nil {
		return err
	}
	return nil
}

// cacheDir is OS-appropriate per-user storage for downloaded helpers.
func cacheDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			return "", fmt.Errorf("LOCALAPPDATA not set")
		}
		return filepath.Join(local, "tun0access", "cache"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Caches", "tun0access"), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".cache", "tun0access"), nil
	}
}

// shortChecksum is a debug helper to fingerprint cached binaries.
func shortChecksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}
