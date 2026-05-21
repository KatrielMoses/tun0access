package cmd

import (
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tun0access/tun0access/internal/backend"
	"github.com/tun0access/tun0access/internal/openvpn"
	"github.com/tun0access/tun0access/internal/ui"
)

var (
	flagCountry  string
	flagBackend  string
	flagNoInstall bool
)

var connectCmd = &cobra.Command{
	Use:   "connect [country-code]",
	Short: "Connect to a free VPN server (optionally pinned to a country)",
	Long: `Fetches the current server list from every enabled backend, lets you pick
a country, then hands the selected server's config to openvpn. The process
runs in the foreground — Ctrl-C disconnects.

  tun0access connect          # interactive picker
  tun0access connect JP       # connect to Japan, pick best server`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&flagCountry, "country", "", "ISO-3166 alpha-2 country code (e.g. JP, US)")
	connectCmd.Flags().StringVar(&flagBackend, "backend", "", "restrict to a single backend (e.g. vpngate)")
	connectCmd.Flags().BoolVar(&flagNoInstall, "no-install", false, "do not attempt to auto-install openvpn if missing")
}

func runConnect(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cc := strings.ToUpper(flagCountry)
	if cc == "" && len(args) == 1 {
		cc = strings.ToUpper(args[0])
	}

	fmt.Println("• Checking for openvpn…")
	bin, err := openvpn.EnsureInstalled(ctx, !flagNoInstall)
	if err != nil {
		return err
	}
	fmt.Println("  found:", bin)

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
	fmt.Printf("• Connecting via %s (%s) — backend=%s, score=%d, ping=%dms\n",
		chosen.CountryLong, chosen.CountryShort, chosen.Backend, chosen.Score, chosen.PingMS)
	fmt.Println("  Ctrl-C to disconnect.")
	fmt.Println()

	opts := openvpn.RunOptions{
		Binary: bin,
		Config: chosen.Config,
	}
	if chosen.Credentials != nil {
		opts.Credentials = &openvpn.Credentials{
			Username: chosen.Credentials.Username,
			Password: chosen.Credentials.Password,
		}
	}
	return openvpn.Run(ctx, opts)
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

