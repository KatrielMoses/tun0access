package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/KatrielMoses/tun0access/internal/asncheck"
	"github.com/KatrielMoses/tun0access/internal/backend"
	"github.com/KatrielMoses/tun0access/internal/diagnose"
	"github.com/KatrielMoses/tun0access/internal/exitcheck"
	"github.com/KatrielMoses/tun0access/internal/openvpn"
	"github.com/KatrielMoses/tun0access/internal/proxy"
	"github.com/KatrielMoses/tun0access/internal/runtools"
	"github.com/KatrielMoses/tun0access/internal/speedtest"
	"github.com/KatrielMoses/tun0access/internal/ui"
	"github.com/spf13/cobra"
)

const (
	// readyDeadline bounds the "connecting…" phase of each attempt.
	readyDeadline = 45 * time.Second
	// maxAttempts is the per-country retry ceiling. With CDN detection at
	// ingest (v0.4.8) the candidate pool is much cleaner, but a few servers
	// still slip through and exit in the wrong country — five tries gives
	// the auto-retry-on-mismatch logic enough headroom to land on a real
	// in-country server within a few seconds.
	maxAttempts = 5
)

var (
	flagCountry   string
	flagBackend   string
	flagNoInstall bool
	flagVerbose   bool
	flagNoProbe   bool
)

var connectCmd = &cobra.Command{
	Use:   "connect [country-code]",
	Short: "Connect to a free VPN / proxy server (optionally pinned to a country)",
	Long: `Fetches the current server list, lets you pick a country, then dispatches
to the right engine (openvpn for VPN protocols, sing-box for shadowsocks /
vmess / vless / trojan / tuic / hysteria2 / wireguard). After the engine
reports ready we run a quick
bandwidth probe through the tunnel; if the server is too slow we silently
try another one. Foreground process — Ctrl-C disconnects.

  tun0access connect            # interactive picker
  tun0access connect JP         # connect to Japan, pick best server
  tun0access connect JP -v      # same, with raw engine output for debugging
  tun0access connect --no-probe # skip the bandwidth check (one shot)`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&flagCountry, "country", "", "ISO-3166 alpha-2 country code (e.g. JP, US)")
	connectCmd.Flags().StringVar(&flagBackend, "backend", "", "restrict to a single backend (e.g. vpngate, riseup, ss-aggregator)")
	connectCmd.Flags().BoolVar(&flagNoInstall, "no-install", false, "do not auto-install openvpn or sing-box if missing")
	connectCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "show raw engine output (openvpn / sing-box logs)")
	connectCmd.Flags().BoolVar(&flagNoProbe, "no-probe", false, "skip the post-connect bandwidth probe and auto-retry")
}

func runConnect(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cc := strings.ToUpper(flagCountry)
	if cc == "" && len(args) == 1 {
		cc = strings.ToUpper(args[0])
	}

	// Pre-resolve the bandwidth-probe target before any tunnel is up.
	// Otherwise the post-connect probe's DNS lookup goes through the proxy
	// and fails as "no such host" even on tunnels that work for raw TCP.
	if !flagNoProbe {
		speedtest.Prepare(ctx)
	}

	fmt.Println("• Fetching server list…")
	servers, errs := backend.FetchAll(ctx)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "  warning:", e)
	}
	if flagBackend != "" {
		servers = filterByBackend(servers, flagBackend)
	}
	if len(servers) == 0 {
		return fmt.Errorf("no servers available from any backend")
	}
	fmt.Printf("  got %d servers across %d countries\n", len(servers), countCountries(servers))

	if cc == "" {
		entries := ui.BuildEntries(servers)
		picked, err := ui.PickCountry(entries)
		if err != nil {
			return err
		}
		if picked == "" {
			fmt.Println("cancelled")
			return nil
		}
		cc = picked
	}

	// Retry loop: try up to maxAttempts servers in the chosen country. Each
	// attempt = pick a server, connect, probe; on probe failure mark the
	// server attempted and loop. Stop early on user Ctrl-C or hard error.
	attempted := map[string]bool{}
	var lastReason string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		chosen := pickServer(servers, cc, attempted)
		if chosen == nil {
			break
		}
		attempted[chosen.ID] = true

		fmt.Printf("• Attempt %d/%d: %s (%s) — backend=%s, protocol=%s\n",
			attempt, maxAttempts, chosen.CountryLong, chosen.CountryShort, chosen.Backend, chosen.Protocol)

		output, runErr, verdict := attemptConnect(ctx, chosen)

		// User Ctrl-C? Stop cleanly — Ctrl-C wins over every other outcome.
		if ctx.Err() != nil {
			fmt.Println("• Disconnected.")
			return nil
		}

		// Probe verdicts and engine errors are mutually exclusive in
		// practice — we cancelled engine only because probe was bad, so
		// engine's "error" is context.Canceled which we ignore.
		switch verdict {
		case verdictGood:
			// Engine exited on its own. Either Ctrl-C path raced with us,
			// or the engine died after a healthy probe. Treat as done.
			return nil
		case verdictSlow:
			lastReason = fmt.Sprintf("server too slow (~%.2f Mbps)", float64(lastMbps.Load())/100)
			continue
		case verdictUnreachable:
			lastReason = "tunnel up but couldn't reach the internet"
			continue
		case verdictGeoMismatch:
			lastReason = "server exited in the wrong country"
			if e := lastExit.Load(); e != nil {
				lastReason = fmt.Sprintf("server exited in %s (%s), not %s", e.City, e.CountryCode, cc)
			}
			continue
		case verdictEngineFailed:
			// Engine blew up before we could probe. Most common cause is a
			// server-specific config quirk that our parser didn't catch (new
			// cipher, new flow, etc). Retry with the next server unless the
			// diagnosis says it's our bug or needs user action.
			d := diagnose.Recognise(output)
			if d != nil && (d.Fault == diagnose.FaultOurs || d.Fault == diagnose.FaultUser) {
				reportFailure(chosen, output, runErr)
				return ErrSilent
			}
			lastReason = "engine refused this server's config"
			if hint := lastMeaningfulLine(output); hint != "" {
				lastReason = hint
			}
			continue
		}
	}

	if lastReason == "" {
		fmt.Printf("\n✗ No more servers to try in %s.\n", cc)
		return ErrSilent
	}
	fmt.Printf("\n✗ Tried %d servers in %s — all unusable (last: %s).\n", maxAttempts, cc, lastReason)
	fmt.Println("  → Try a different country, or re-run later — free servers come and go.")
	return ErrSilent
}

type verdict int

const (
	verdictGood         verdict = iota // engine ran to its natural end (Ctrl-C / graceful)
	verdictSlow                        // probe came back under MinUsableMbps
	verdictUnreachable                 // probe failed entirely
	verdictEngineFailed                // engine crashed before we could probe
	verdictGeoMismatch                 // probe + speed ok, but exit IP is in the wrong country
)

// lastExit stashes the most recent exit-IP result so the retry-loop can
// quote it in failure messages without complex value passing. Reset per attempt.
var lastExit atomic.Pointer[exitcheck.Exit]

// lastMbps stores the most recent measured throughput (×100, fixed-point) so
// retry messages can quote it without complex value passing. It's reset per
// attempt.
var lastMbps atomic.Int64

// attemptConnect runs one connection attempt: start engine, on ready run a
// probe in the background, cancel engine if probe is bad. Returns captured
// engine output, the engine's exit error, and a verdict the loop uses.
func attemptConnect(parentCtx context.Context, s *backend.Server) (string, error, verdict) {
	// Flags the probe goroutine sets so the caller knows why the engine
	// stopped.
	var (
		probeRan    atomic.Bool
		probeSlow   atomic.Bool
		probeFailed atomic.Bool
		geoMismatch atomic.Bool
	)

	// Engine context: we cancel it from the probe when the server is bad.
	runCtx, cancelRun := context.WithCancel(parentCtx)
	defer cancelRun()

	onReady := func() {
		if flagNoProbe {
			fmt.Println("• Connected ✓ — Ctrl-C to disconnect")
			return
		}
		fmt.Println("• Connected ✓ — testing tunnel…")
		go func() {
			res, err := speedtest.Probe(runCtx)
			probeRan.Store(true)
			if err != nil {
				fmt.Printf("  ✗ Server isn't passing real traffic — %s. Trying another…\n", summariseProbeErr(err))
				probeFailed.Store(true)
				cancelRun()
				return
			}
			lastMbps.Store(int64(res.Mbps * 100))
			if !res.IsUsable() {
				fmt.Printf("  ✗ Too slow (%.2f Mbps) — trying another server…\n", res.Mbps)
				probeSlow.Store(true)
				cancelRun()
				return
			}

			// Speed is fine. Now check where we ACTUALLY exit — server
			// labels lie all the time (CDN-fronted, mislabelled, etc.) and
			// the user cares about the exit, not the label.
			exit, exitErr := exitcheck.Where(runCtx)
			if exitErr != nil {
				// Exit check failed — show speed only and keep going. We
				// can't tell whether the country is right, but the tunnel
				// passes traffic, which is the bar the user actually cares
				// about. Don't penalise transient ip-api.com hiccups.
				fmt.Printf("  ✓ %.2f Mbps — ready (exit country unknown). Ctrl-C to disconnect.\n", res.Mbps)
				return
			}

			// XX is the explicit "anycast / CDN-fronted" bucket — exit
			// country varying IS the contract, so we don't enforce a match.
			if s.CountryShort != "XX" {
				if exit.CountryCode != s.CountryShort {
					fmt.Printf("  ✗ Exits in %s (%s), not %s as labelled — trying another…\n",
						exit.City, exit.CountryCode, s.CountryShort)
					lastExit.Store(exit)
					geoMismatch.Store(true)
					cancelRun()
					return
				}
				// Country matched. Now check ASN: even if the exit IP geolocates
				// to the right country, an ASN belonging to Cloudflare /
				// hyperscaler clouds / known WARP-forwarders means the traffic
				// is going through anycast and the user isn't really on the
				// labelled country's local network. Trigger a retry.
				if susp, reason := asncheck.IsSuspicious(exit.ASN); susp {
					fmt.Printf("  ✗ Exits via %s (AS%d %s) — that's a forward-chain, not a real %s server. Trying another…\n",
						reason, exit.ASN, exit.ASOrg, s.CountryShort)
					lastExit.Store(exit)
					geoMismatch.Store(true)
					cancelRun()
					return
				}
			}
			fmt.Printf("  ✓ %.2f Mbps — exit in %s (%s). Ctrl-C to disconnect.\n",
				res.Mbps, exit.City, exit.CountryCode)
		}()
	}

	output, runErr := dispatchEngine(runCtx, s, onReady)

	// If the user Ctrl-C'd, the parent ctx is also done — short-circuit.
	if parentCtx.Err() != nil {
		return output, runErr, verdictGood
	}
	if probeSlow.Load() {
		return output, runErr, verdictSlow
	}
	if probeFailed.Load() {
		return output, runErr, verdictUnreachable
	}
	if geoMismatch.Load() {
		return output, runErr, verdictGeoMismatch
	}
	// Engine exited before probe even started (or before it finished and
	// without us cancelling). That's an engine-side failure.
	if !probeRan.Load() && runErr != nil {
		return output, runErr, verdictEngineFailed
	}
	return output, runErr, verdictGood
}

func dispatchEngine(ctx context.Context, s *backend.Server, onReady func()) (string, error) {
	switch s.Protocol {
	case "openvpn":
		bin, err := openvpn.EnsureInstalled(ctx, !flagNoInstall)
		if err != nil {
			return "", err
		}
		fmt.Println("• Engine: openvpn — establishing tunnel (can take 10-30s)…")
		opts := openvpn.RunOptions{
			Binary:        bin,
			Config:        s.Config,
			Verbose:       flagVerbose,
			OnReady:       onReady,
			ReadyDeadline: readyDeadline,
		}
		if s.Credentials != nil {
			opts.Credentials = &openvpn.Credentials{
				Username: s.Credentials.Username,
				Password: s.Credentials.Password,
			}
		}
		return openvpn.Run(ctx, opts)

	case "shadowsocks", "vmess", "vless", "trojan", "tuic", "hysteria2", "wireguard":
		bin, err := proxy.EnsureSingBox(ctx)
		if err != nil {
			return "", fmt.Errorf("sing-box: %w", err)
		}
		var out proxy.Outbound
		if err := json.Unmarshal(s.Config, &out); err != nil {
			return "", fmt.Errorf("unmarshal outbound: %w", err)
		}
		fmt.Println("• Engine: sing-box — establishing tunnel…")
		return proxy.Run(ctx, proxy.RunOptions{
			Binary:        bin,
			Out:           &out,
			Verbose:       flagVerbose,
			OnReady:       onReady,
			ReadyDeadline: readyDeadline,
		})

	default:
		return "", fmt.Errorf("unknown protocol %q on server %s", s.Protocol, s.ID)
	}
}

// reportFailure prints a friendly diagnosis for a failed engine. Called only
// when the engine itself errored — probe-driven retries don't pass through.
func reportFailure(s *backend.Server, output string, runErr error) {
	fmt.Println()

	if errors.Is(runErr, runtools.TimedOut) {
		fmt.Printf("✗ This server never became ready (timed out after %s).\n", readyDeadline)
		fmt.Println("  → The server is likely down or unreachable. Re-run to try a different one.")
		if flagVerbose {
			if hint := lastMeaningfulLine(output); hint != "" {
				fmt.Println("  Last log line:", hint)
			}
		}
		return
	}

	d := diagnose.Recognise(output)
	if d == nil {
		fmt.Println("✗ Connection failed (unrecognised error).")
		if hint := lastMeaningfulLine(output); hint != "" {
			fmt.Println("  Hint:", hint)
		}
		if flagVerbose {
			fmt.Println("  Raw exit error:", runErr)
		} else {
			fmt.Println("  Run again with -v for full engine output.")
		}
		fmt.Println("  Or try another country — free servers come and go.")
		return
	}

	icon := "✗"
	prefix := "Connection failed"
	switch d.Fault {
	case diagnose.FaultServer:
		prefix = "This server is broken"
	case diagnose.FaultUser:
		prefix = "Action needed"
	case diagnose.FaultOurs:
		icon = "!"
		prefix = "tun0access bug"
	}

	fmt.Printf("%s %s — %s\n", icon, prefix, d.Summary)
	fmt.Printf("  → %s\n", d.Action)

	if d.Fault == diagnose.FaultOurs {
		if hint := lastMeaningfulLine(output); hint != "" {
			fmt.Println("  Underlying:", hint)
		}
	}
	if flagVerbose {
		fmt.Println("\n  Raw exit error:", runErr)
	}
}

// ErrSilent — runConnect printed everything already; main() just exits 1.
var ErrSilent = errors.New("silent")

// summariseProbeErr boils raw network errors down to a 5-word verdict for
// the retry message. We don't need the full stack — just enough for the user
// to know "tunnel is broken, not just slow".
func summariseProbeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "context deadline exceeded"), strings.Contains(s, "i/o timeout"):
		return "request timed out"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "connection reset"):
		return "connection reset"
	case strings.Contains(s, "no such host"), strings.Contains(s, "lookup"):
		return "DNS through tunnel broken"
	case strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"):
		return "no route to internet"
	case strings.Contains(s, "truncated"):
		return "connection dropped mid-transfer"
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

// lastMeaningfulLine returns the last non-empty output line, trimmed and
// truncated.
func lastMeaningfulLine(output string) string {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s := strings.TrimSpace(lines[i])
		if s == "" {
			continue
		}
		if idx := strings.Index(s, "] "); idx >= 0 && idx < 40 {
			s = strings.TrimSpace(s[idx+2:])
		}
		if len(s) > 220 {
			s = s[:220] + "…"
		}
		return s
	}
	return ""
}

// pickServer chooses among the top 5 servers in a country at random,
// skipping any that the caller has already attempted in this session.
func pickServer(servers []backend.Server, cc string, exclude map[string]bool) *backend.Server {
	grouped := backend.GroupByCountry(servers)
	pool := grouped[cc]
	if len(pool) == 0 {
		return nil
	}
	var available []backend.Server
	for _, s := range pool {
		if !exclude[s.ID] {
			available = append(available, s)
		}
	}
	if len(available) == 0 {
		return nil
	}
	top := available
	if len(top) > 5 {
		top = top[:5]
	}
	s := top[rand.IntN(len(top))]
	return &s
}

func filterByBackend(servers []backend.Server, name string) []backend.Server {
	out := servers[:0]
	for _, s := range servers {
		if s.Backend == name {
			out = append(out, s)
		}
	}
	return out
}

func countCountries(servers []backend.Server) int {
	seen := map[string]struct{}{}
	for _, s := range servers {
		if s.CountryShort != "" {
			seen[s.CountryShort] = struct{}{}
		}
	}
	return len(seen)
}
