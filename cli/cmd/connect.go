package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KatrielMoses/tun0access/internal/backend"
	"github.com/KatrielMoses/tun0access/internal/openvpn"
	"github.com/KatrielMoses/tun0access/internal/proxy"
	"github.com/KatrielMoses/tun0access/internal/ui"
	"github.com/spf13/cobra"
)

var (
	flagCountry   string
	flagBackend   string
	flagNoInstall bool
)

var connectCmd = &cobra.Command{
	Use:   "connect [country-code]",
	Short: "Connect to a free VPN / proxy server (optionally pinned to a country)",
	Long: `Fetches the current server list from every enabled backend, lets you pick
a country, then dispatches to the right engine (openvpn for VPN protocols,
sing-box for shadowsocks / vmess / vless / trojan). Foreground process —
Ctrl-C disconnects.

  tun0access connect          # interactive picker
  tun0access connect JP       # connect to Japan, pick best server`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&flagCountry, "country", "", "ISO-3166 alpha-2 country code (e.g. JP, US)")
	connectCmd.Flags().StringVar(&flagBackend, "backend", "", "restrict to a single backend (e.g. vpngate, riseup, ss-aggregator)")
	connectCmd.Flags().BoolVar(&flagNoInstall, "no-install", false, "do not auto-install openvpn or sing-box if missing")
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
	fmt.Printf("• Connecting via %s (%s) — backend=%s, protocol=%s, score=%d\n",
		chosen.CountryLong, chosen.CountryShort, chosen.Backend, chosen.Protocol, chosen.Score)
	fmt.Println("  Ctrl-C to disconnect.")
	fmt.Println()

	switch chosen.Protocol {
	case "openvpn":
		return runOpenVPN(ctx, chosen)
	case "shadowsocks", "vmess", "vless", "trojan":
		return runSingBox(ctx, chosen)
	default:
		return fmt.Errorf("unknown protocol %q on server %s", chosen.Protocol, chosen.ID)
	}
}

func runOpenVPN(ctx context.Context, s *backend.Server) error {
	fmt.Println("• Checking for openvpn…")
	bin, err := openvpn.EnsureInstalled(ctx, !flagNoInstall)
	if err != nil {
		return err
	}
	fmt.Println("  found:", bin)

	opts := openvpn.RunOptions{Binary: bin, Config: s.Config}
	if s.Credentials != nil {
		opts.Credentials = &openvpn.Credentials{
			Username: s.Credentials.Username,
			Password: s.Credentials.Password,
		}
	}
	return openvpn.Run(ctx, opts)
}

func runSingBox(ctx context.Context, s *backend.Server) error {
	fmt.Println("• Preparing sing-box…")
	bin, err := proxy.EnsureSingBox(ctx)
	if err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	fmt.Println("  found:", bin)

	var out proxy.Outbound
	if err := json.Unmarshal(s.Config, &out); err != nil {
		return fmt.Errorf("unmarshal outbound: %w", err)
	}
	return proxy.Run(ctx, bin, &out)
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
