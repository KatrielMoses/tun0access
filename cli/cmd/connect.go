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
	"syscall"
	"time"

	"github.com/KatrielMoses/tun0access/internal/backend"
	"github.com/KatrielMoses/tun0access/internal/diagnose"
	"github.com/KatrielMoses/tun0access/internal/openvpn"
	"github.com/KatrielMoses/tun0access/internal/proxy"
	"github.com/KatrielMoses/tun0access/internal/runtools"
	"github.com/KatrielMoses/tun0access/internal/ui"
	"github.com/spf13/cobra"
)

// readyDeadline bounds the "connecting…" phase. If neither engine reaches its
// success marker in this time, we kill it and tell the user the server is
// dead. Beats the previous behaviour of hanging silently for 15 minutes.
const readyDeadline = 45 * time.Second

var (
	flagCountry   string
	flagBackend   string
	flagNoInstall bool
	flagVerbose   bool
)

var connectCmd = &cobra.Command{
	Use:   "connect [country-code]",
	Short: "Connect to a free VPN / proxy server (optionally pinned to a country)",
	Long: `Fetches the current server list from every enabled backend, lets you pick
a country, then dispatches to the right engine (openvpn for VPN protocols,
sing-box for shadowsocks / vmess / vless / trojan). Foreground process —
Ctrl-C disconnects.

  tun0access connect            # interactive picker
  tun0access connect JP         # connect to Japan, pick best server
  tun0access connect JP -v      # same, with raw engine output for debugging`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&flagCountry, "country", "", "ISO-3166 alpha-2 country code (e.g. JP, US)")
	connectCmd.Flags().StringVar(&flagBackend, "backend", "", "restrict to a single backend (e.g. vpngate, riseup, ss-aggregator)")
	connectCmd.Flags().BoolVar(&flagNoInstall, "no-install", false, "do not auto-install openvpn or sing-box if missing")
	connectCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "show raw engine output (openvpn / sing-box logs)")
}

func runConnect(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cc := strings.ToUpper(flagCountry)
	if cc == "" && len(args) == 1 {
		cc = strings.ToUpper(args[0])
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

	chosen := pickServer(servers, cc)
	if chosen == nil {
		return fmt.Errorf("no servers available for country %q", cc)
	}
	fmt.Printf("• Connecting via %s (%s) — backend=%s, protocol=%s\n",
		chosen.CountryLong, chosen.CountryShort, chosen.Backend, chosen.Protocol)

	output, runErr := dispatchEngine(ctx, chosen)

	// Ctrl-C is the normal way to disconnect — don't treat it as failure.
	if ctx.Err() != nil {
		fmt.Println("\n• Disconnected.")
		return nil
	}
	if runErr == nil {
		return nil
	}
	reportFailure(chosen, output, runErr)
	return ErrSilent
}

// ErrSilent is returned when runConnect has already printed a user-facing
// message and main() should exit non-zero without adding more output.
var ErrSilent = errors.New("silent")

func dispatchEngine(ctx context.Context, s *backend.Server) (string, error) {
	switch s.Protocol {
	case "openvpn":
		return runOpenVPN(ctx, s)
	case "shadowsocks", "vmess", "vless", "trojan":
		return runSingBox(ctx, s)
	default:
		return "", fmt.Errorf("unknown protocol %q on server %s", s.Protocol, s.ID)
	}
}

func runOpenVPN(ctx context.Context, s *backend.Server) (string, error) {
	bin, err := openvpn.EnsureInstalled(ctx, !flagNoInstall)
	if err != nil {
		return "", err
	}
	fmt.Println("• Engine: openvpn — establishing tunnel (this can take 10-30s)…")
	opts := openvpn.RunOptions{
		Binary:        bin,
		Config:        s.Config,
		Verbose:       flagVerbose,
		OnReady:       func() { fmt.Println("• Connected ✓ — Ctrl-C to disconnect") },
		ReadyDeadline: readyDeadline,
	}
	if s.Credentials != nil {
		opts.Credentials = &openvpn.Credentials{
			Username: s.Credentials.Username,
			Password: s.Credentials.Password,
		}
	}
	return openvpn.Run(ctx, opts)
}

func runSingBox(ctx context.Context, s *backend.Server) (string, error) {
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
		OnReady:       func() { fmt.Println("• Connected ✓ — Ctrl-C to disconnect") },
		ReadyDeadline: readyDeadline,
	})
}

// reportFailure prints a friendly diagnosis for a failed connection. If the
// captured output matches a known pattern we attribute fault and suggest an
// action; otherwise we hint at -v for raw logs.
func reportFailure(s *backend.Server, output string, runErr error) {
	fmt.Println()

	// Timeout is its own thing — we killed the subprocess because the engine
	// started but never confirmed connected. Almost always means the server
	// is dead, not a tun0access issue.
	if errors.Is(runErr, runtools.TimedOut) {
		fmt.Printf("✗ This server never became ready (timed out after %s).\n", readyDeadline)
		fmt.Println("  → The server is likely down or unreachable. Re-run to pick a different one.")
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

	// For "ours" diagnoses (tun0access bugs) always surface the underlying
	// line so reports back to us are immediately actionable. Server/user
	// faults don't need this — the summary already tells the user what to do.
	if d.Fault == diagnose.FaultOurs {
		if hint := lastMeaningfulLine(output); hint != "" {
			fmt.Println("  Underlying:", hint)
		}
	}

	if flagVerbose {
		fmt.Println("\n  Raw exit error:", runErr)
	}
}

// lastMeaningfulLine returns the last non-empty output line, trimmed and
// truncated, that isn't pure noise (timestamps, blank lines). It's the
// "best guess" hint we offer when our pattern bank doesn't match.
func lastMeaningfulLine(output string) string {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s := strings.TrimSpace(lines[i])
		if s == "" {
			continue
		}
		// Drop common log prefixes (timestamps, level brackets) to focus on
		// the actual message.
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

// pickServer chooses among the top 5 servers in a country at random so we
// spread load and don't hammer a single endpoint.
func pickServer(servers []backend.Server, cc string) *backend.Server {
	grouped := backend.GroupByCountry(servers)
	pool := grouped[cc]
	if len(pool) == 0 {
		return nil
	}
	top := pool
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
