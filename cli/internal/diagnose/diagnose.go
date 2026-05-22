// Package diagnose translates raw openvpn / sing-box log lines into clear
// user-facing diagnoses with fault attribution. The goal: a non-technical
// user sees "this server is broken, try another country" instead of a wall
// of TLS handshake noise.
package diagnose

import (
	"regexp"
	"strings"
)

// Fault tells the user who's at fault and what to do about it.
type Fault string

const (
	FaultServer  Fault = "server"  // the chosen server is broken or down — try another
	FaultUser    Fault = "user"    // user can fix (admin required, network down, etc.)
	FaultOurs    Fault = "ours"    // tun0access bug — should be reported
	FaultUnknown Fault = "unknown" // we couldn't classify it
)

// Diagnosis is what we surface to the user when something fails.
type Diagnosis struct {
	Fault   Fault
	Summary string // one-line headline
	Action  string // what the user should do
}

// Recognise scans captured subprocess output (combined stdout+stderr) for
// known failure patterns. Returns nil if nothing matched — the caller should
// then fall back to a generic "unexpected error, re-run with -v" message.
func Recognise(output string) *Diagnosis {
	for _, p := range patterns {
		if p.match.MatchString(output) {
			d := p.diag
			return &d
		}
	}
	return nil
}

// SuccessMarkers are the substrings that indicate a tunnel is fully up.
// Used by the runner to print "Connected" once we see one.
var SuccessMarkers = []string{
	"Initialization Sequence Completed", // openvpn
	"sing-box started",                  // sing-box ≥1.12
	"started (",                         // sing-box older formats e.g. "tun started (..."
	"inbound/tun",                       // sing-box tun ready
}

// IsSuccess returns true if line contains any success marker.
func IsSuccess(line string) bool {
	for _, m := range SuccessMarkers {
		if strings.Contains(line, m) {
			return true
		}
	}
	return false
}

type pattern struct {
	match *regexp.Regexp
	diag  Diagnosis
}

// patterns are checked in order — first match wins. Put specific patterns
// before generic ones.
var patterns = []pattern{
	// ─── OpenVPN ────────────────────────────────────────────────────────
	{
		match: regexp.MustCompile(`AUTH(?:_FAILED|: Received control message: AUTH_FAILED)`),
		diag: Diagnosis{
			Fault:   FaultServer,
			Summary: "This server rejected the connection (auth failed).",
			Action:  "Try another country, or re-run — we'll pick a different server.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)Cannot open TUN/TAP|Failed to open tun/tap|TUN/TAP-style tunnel|All TAP-Windows adapters.*are currently in use`),
		diag: Diagnosis{
			Fault:   FaultUser,
			Summary: "Couldn't create the VPN network adapter.",
			Action:  "Re-run from an elevated terminal (Administrator on Windows, sudo on Linux/macOS).",
		},
	},
	{
		match: regexp.MustCompile(`(?i)failed to negotiate cipher`),
		diag: Diagnosis{
			Fault:   FaultServer,
			Summary: "This server uses a cipher our build can't negotiate.",
			Action:  "Try another country — most servers are fine, this one's an outlier.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)Endtag </?ca> missing|OPTIONS ERROR: failed to apply push options|Bad encapsulated packet`),
		diag: Diagnosis{
			Fault:   FaultOurs,
			Summary: "We sent a malformed config to OpenVPN — that's a bug in tun0access.",
			Action:  "Please report this at https://github.com/KatrielMoses/tun0access/issues. Try another country meanwhile.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)TLS Error: TLS key negotiation failed|TLS handshake failed`),
		diag: Diagnosis{
			Fault:   FaultServer,
			Summary: "TLS handshake with this server failed (it's likely overloaded or down).",
			Action:  "Try another country, or re-run for a fresh pick.",
		},
	},

	// ─── sing-box / proxy stack ────────────────────────────────────────
	{
		match: regexp.MustCompile(`ENABLE_DEPRECATED_LEGACY_DNS_SERVERS|legacy DNS servers is deprecated`),
		diag: Diagnosis{
			Fault:   FaultOurs,
			Summary: "tun0access generated a config using a deprecated sing-box format.",
			Action:  "Update tun0access — this is fixed in a newer build. Run the install one-liner to refresh.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)outbound handshake failed|connect to .+: i/o timeout|context deadline exceeded.*dial`),
		diag: Diagnosis{
			Fault:   FaultServer,
			Summary: "Couldn't reach this server (it's not responding).",
			Action:  "Try another country — we'll pick a different one. Free servers come and go.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)tls: handshake failure|tls: bad certificate|x509: certificate`),
		diag: Diagnosis{
			Fault:   FaultServer,
			Summary: "TLS to this server failed — its certificate is rejected by our trust store.",
			Action:  "Try another country, or re-run.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)operation not permitted|access is denied|permission denied.*tun`),
		diag: Diagnosis{
			Fault:   FaultUser,
			Summary: "Permission denied creating the TUN device.",
			Action:  "Re-run from an elevated terminal (Administrator on Windows, sudo on Linux/macOS).",
		},
	},
	{
		match: regexp.MustCompile(`(?i)wintun.*not found|failed to load wintun|wintun\.dll`),
		diag: Diagnosis{
			Fault:   FaultOurs,
			Summary: "Windows' Wintun driver is missing or didn't load.",
			Action:  "Reinstall tun0access via the one-liner so the bundled driver is restored.",
		},
	},

	// ─── network-level (applies to both engines) ────────────────────────
	{
		match: regexp.MustCompile(`(?i)no such host|name resolution failed|dial.*lookup`),
		diag: Diagnosis{
			Fault:   FaultUser,
			Summary: "Can't resolve the server's hostname.",
			Action:  "Check your internet connection (and DNS), then re-run.",
		},
	},
	{
		match: regexp.MustCompile(`(?i)connection refused|network is unreachable|no route to host`),
		diag: Diagnosis{
			Fault:   FaultServer,
			Summary: "Server is down or actively rejecting connections.",
			Action:  "Try another country.",
		},
	},
}
