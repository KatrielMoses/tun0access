// Package asncheck looks up the ASN and operator name of an IP address and
// flags whether that ASN belongs to a known forwarder / CDN / anycast pool.
//
// The "I picked HK, exited in IN" failure mode in free Trojan/VLESS configs
// almost always comes from a VPS that itself internally tunnels through
// Cloudflare WARP (or similar) before egressing. The VPS's own IP is
// genuinely in HK, so geoIP-by-IP labels it "HK" — but its exit isn't there.
// You can't see the forward-chain from outside the tunnel; what you CAN see
// is that the VPS sits on an ASN historically used for these setups
// (M247, Zenlayer, hyperscaler cloud ASNs). Filter those out at ingest and
// pick from the remainder first.
//
// Dataset: https://iptoasn.com/data/ip2asn-combined.tsv.gz — daily-updated
// public CC0 dump, ~9 MB gzipped, ~700k IP ranges covering both v4 and v6.
package asncheck

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dataURL  = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
	cacheTTL = 24 * time.Hour
)

// SuspiciousASNs is the curated list synthesised from the three research
// reports (Sonnet, GPT, Gemini all agreed on the core list; Sonnet added
// the WARP-prevalent bulk-VPS providers explicitly observed in HK pools).
//
// The value is a short human-readable reason for the flag.
var SuspiciousASNs = map[uint32]string{
	// CDN / Anycast (forward path always hits an edge POP)
	13335:  "Cloudflare",
	209242: "Cloudflare",
	395747: "Cloudflare",
	20940:  "Akamai",
	16625:  "Akamai CDN",
	32787:  "Akamai",
	35994:  "Akamai",
	54113:  "Fastly",
	60068:  "CDN77",
	200325: "Bunny CDN",
	199524: "Gcore",
	202422: "Gcore",

	// Hyperscaler clouds (free configs commonly tunnel through GCP/Azure/etc
	// edges; not always WARP-chained but exit location is unpredictable)
	16509:  "AWS",
	14618:  "AWS us-east",
	15169:  "Google (incl. WARP-exit paths)",
	396982: "Google Cloud",
	8075:   "Microsoft Azure",
	31898:  "Oracle Cloud",
	132203: "Tencent Cloud",
	45090:  "Tencent Cloud (HK)",
	37963:  "Alibaba Cloud",
	45102:  "Alibaba Cloud",

	// Bulk-VPS providers where WARP-forwarding is endemic in free configs
	// (Sonnet's specific HK-focused finding from the research sweep)
	9009:  "M247 (high WARP-forwarder prevalence)",
	24429: "Zenlayer (HK re-sellers commonly WARP-forward)",
}

// Entry is one row from the ip2asn TSV.
type Entry struct {
	Start, End netip.Addr
	ASN        uint32
	Org        string
}

// Database is the in-memory lookup table. Two sorted slices (v4 + v6),
// binary-searched per query. ~50 MB resident after parse — acceptable for
// a CLI invocation.
type Database struct {
	HTTP *http.Client

	mu    sync.RWMutex
	ready bool
	loadErr error
	v4    []Entry
	v6    []Entry
}

// New returns an empty Database. Prepare loads the data.
func New() *Database {
	return &Database{HTTP: &http.Client{Timeout: 90 * time.Second}}
}

// Prepare downloads the ip2asn dataset (or reuses the disk cache) and parses
// it into memory. Safe to call concurrently; only the first call does work.
func (d *Database) Prepare(ctx context.Context) error {
	d.mu.Lock()
	if d.ready {
		err := d.loadErr
		d.mu.Unlock()
		return err
	}
	d.ready = true
	d.mu.Unlock()

	data, err := d.loadOrFetch(ctx)
	if err != nil {
		d.mu.Lock()
		d.loadErr = err
		d.mu.Unlock()
		return err
	}
	if err := d.parse(data); err != nil {
		d.mu.Lock()
		d.loadErr = err
		d.mu.Unlock()
		return err
	}
	return nil
}

// Lookup returns the ASN and organization name for an IP. The (0, "", false)
// triple means "no match" — typically because the IP is in unrouted space or
// we never got the dataset loaded.
func (d *Database) Lookup(ip netip.Addr) (asn uint32, org string, ok bool) {
	if !ip.IsValid() {
		return 0, "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	pool := d.v4
	if ip.Is6() && !ip.Is4In6() {
		pool = d.v6
	}
	if len(pool) == 0 {
		return 0, "", false
	}
	// sort.Search finds the smallest i such that Start > ip; step back to
	// the candidate range and check it covers ip.
	idx := sort.Search(len(pool), func(i int) bool {
		return pool[i].Start.Compare(ip) > 0
	})
	if idx == 0 {
		return 0, "", false
	}
	e := pool[idx-1]
	if ip.Compare(e.Start) >= 0 && ip.Compare(e.End) <= 0 {
		if e.ASN == 0 {
			return 0, "", false
		}
		return e.ASN, e.Org, true
	}
	return 0, "", false
}

// IsSuspicious reports whether the given ASN is in our forwarder/CDN list.
func IsSuspicious(asn uint32) (bool, string) {
	if asn == 0 {
		return false, ""
	}
	r, ok := SuspiciousASNs[asn]
	return ok, r
}

// DetectByIP combines Lookup + IsSuspicious into one call.
func (d *Database) DetectByIP(ip netip.Addr) (asn uint32, org string, suspicious bool, reason string) {
	asn, org, ok := d.Lookup(ip)
	if !ok {
		return 0, "", false, ""
	}
	suspicious, reason = IsSuspicious(asn)
	return asn, org, suspicious, reason
}

// ParseASNString pulls the numeric ASN out of strings like "AS13335 Cloudflare,
// Inc." — the format ip-api.com returns in its `as` field.
func ParseASNString(s string) uint32 {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToUpper(s), "AS") {
		return 0
	}
	s = s[2:]
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseUint(s[:end], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// ── parsing ─────────────────────────────────────────────────────────────

func (d *Database) parse(gzData []byte) error {
	gz, err := gzip.NewReader(io.LimitReader(bytesReader(gzData), 200<<20))
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	var v4, v6 []Entry
	scanner := bufio.NewScanner(gz)
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// 5 tab-separated fields: start, end, asn, country, org
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 5 {
			continue
		}
		start, err := netip.ParseAddr(parts[0])
		if err != nil {
			continue
		}
		end, err := netip.ParseAddr(parts[1])
		if err != nil {
			continue
		}
		asn, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		entry := Entry{
			Start: start,
			End:   end,
			ASN:   uint32(asn),
			Org:   parts[4],
		}
		if start.Is6() {
			v6 = append(v6, entry)
		} else {
			v4 = append(v4, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	sort.Slice(v4, func(i, j int) bool { return v4[i].Start.Compare(v4[j].Start) < 0 })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Start.Compare(v6[j].Start) < 0 })

	d.mu.Lock()
	d.v4 = v4
	d.v6 = v6
	d.mu.Unlock()
	return nil
}

// ── disk cache ──────────────────────────────────────────────────────────

func cachePath() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "tun0access", "cache", "ip2asn.tsv.gz")
		}
	case "darwin":
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, "Library", "Caches", "tun0access", "ip2asn.tsv.gz")
		}
	default:
		if d, err := os.UserHomeDir(); err == nil {
			return filepath.Join(d, ".cache", "tun0access", "ip2asn.tsv.gz")
		}
	}
	return ""
}

func (d *Database) loadOrFetch(ctx context.Context) ([]byte, error) {
	p := cachePath()
	if p != "" {
		if info, err := os.Stat(p); err == nil && time.Since(info.ModTime()) < cacheTTL {
			if data, err := os.ReadFile(p); err == nil {
				return data, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dataURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download ip2asn: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip2asn HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if p != "" {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, data, 0o600)
	}
	return data, nil
}

// bytesReader avoids importing bytes just for one NewReader call.
type roBytes []byte

func (b roBytes) Read(p []byte) (int, error) {
	n := copy(p, b)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func bytesReader(b []byte) io.Reader {
	// We use a stateful wrapper because compress/gzip wants a stream that
	// returns io.EOF cleanly after exhaustion.
	return &byteStream{buf: b}
}

type byteStream struct {
	buf []byte
	pos int
}

func (s *byteStream) Read(p []byte) (int, error) {
	if s.pos >= len(s.buf) {
		return 0, io.EOF
	}
	n := copy(p, s.buf[s.pos:])
	s.pos += n
	return n, nil
}
