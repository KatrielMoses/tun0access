# tun0access

> One command, free VPN access, many countries. Cross-platform CLI for
> Windows, macOS, and Linux.

`tun0access` is a thin orchestrator over a handful of free open-source VPN
and proxy ecosystems. It aggregates ~**2,000 servers across 63 countries**
from public sources, lets you pick a country interactively, then dispatches
to the right engine (OpenVPN for traditional VPN providers, sing-box for
Shadowsocks / VMess / VLESS / Trojan / TUIC / Hysteria2). After connecting
it runs a real bandwidth probe through the tunnel and silently moves to a
faster server if the first one is too slow.

```
$ tun0access connect
• Fetching server list…
  got 2168 servers across 63 countries
┌─ Choose a country to tunnel through ───────────────────────┐
│ > 🇺🇸  United States   (683 servers)                        │
│   🇨🇦  Canada          (352 servers)                        │
│   🇻🇳  Viet Nam        (144 servers)                        │
│   🇳🇱  Netherlands     (120 servers)                        │
│   🇩🇪  Germany         (114 servers)                        │
│   🇯🇵  Japan           (111 servers)                        │
│   🇭🇰  Hong Kong       (110 servers)                        │
│   …                                                         │
└─────────────────────────────────────────────────────────────┘
• Attempt 1/3: Germany (DE) — backend=ss-aggregator, protocol=trojan
• Engine: sing-box — establishing tunnel…
• Connected ✓ — testing tunnel…
  ✓ 21.20 Mbps — exit in Frankfurt am Main (DE). Ctrl-C to disconnect.
```

## Install

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/KatrielMoses/tun0access/main/install.sh | sh

# Windows PowerShell (elevated)
irm https://raw.githubusercontent.com/KatrielMoses/tun0access/main/install.ps1 | iex

# from source (requires Go 1.25+)
cd cli && go build -o tun0access .
```

The first time you connect to a server that needs it, `tun0access` will
auto-install the required engine:

| Engine    | Used for                          | Install method |
|-----------|-----------------------------------|----------------|
| OpenVPN   | VPN Gate, Riseup, Calyx           | platform package manager (`winget` / `brew` / `apt` / `dnf` / `pacman` / `apk`) |
| sing-box  | Shadowsocks / VMess / VLESS / Trojan / TUIC / Hysteria2 | downloaded directly from official GitHub releases into `~/.cache/tun0access/` |

## Usage

```sh
tun0access connect             # interactive country picker
tun0access connect JP          # pin to Japan, pick best server
tun0access connect DE -v       # same, with raw engine output for debugging
tun0access connect FI --no-probe   # skip bandwidth probe + auto-retry
tun0access list                # full country → server-count table
tun0access status              # is a tunnel adapter currently up?
tun0access doctor              # diagnose engines + backend reachability
```

Connection runs in the foreground. `Ctrl-C` disconnects.

> Linux/macOS re-exec the engine under `sudo` because creating a tun device
> requires root. On Windows, run from an **Administrator** PowerShell — the
> OpenVPN / Wintun drivers can't bind otherwise.

## How a connection actually works

1. **Fetch** — every registered backend's `Fetch(ctx)` is called concurrently.
2. **GeoIP** — server hosts are batched against ip-api.com (with parallel
   DNS resolution and a 24-hour disk-backed cache, so repeat fetches don't
   hammer the API).
3. **Pick** — top-N servers in the chosen country, shuffled to spread load.
4. **Engine dispatch** — protocol on the chosen server picks OpenVPN vs.
   sing-box. Engine is auto-installed if missing.
5. **Ready detection** — the engine's stdout/stderr is captured into a ring
   buffer and watched for protocol-specific success markers
   (`Initialization Sequence Completed` for OpenVPN, `sing-box started` for
   sing-box). 45-second ceiling — if the engine never reaches ready, we
   kill it and report a clean timeout.
6. **Probe** — once ready, download a 200KB payload from Cloudflare via
   IP-direct + `Host: speed.cloudflare.com` (so the probe itself doesn't
   need DNS through the freshly-up tunnel). Anything below 0.5 Mbps gets
   killed and we move to the next server.
7. **Exit-IP check** — query ip-api.com for the actual exit location. If
   it doesn't match the country we connected to, we say so honestly
   instead of silently lying.
8. **Diagnose-on-failure** — any error message gets matched against a
   pattern bank that translates raw engine output into "this is a server
   problem / your problem / our bug, do X".

## Backends

| Backend          | Protocol(s)                                        | Countries (typical) | Notes |
|------------------|----------------------------------------------------|---------------------|-------|
| `vpngate`        | OpenVPN                                            | ~10 (Asia-heavy)    | University of Tsukuba's public relay pool |
| `riseup`         | OpenVPN (anonymous LEAP cert)                      | US, CA, FR, NL      | Run by Riseup nonprofit; no signup |
| `ss-aggregator`  | Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria2 | ~60                 | Aggregates from 9 public GitHub config repos |

Backends auto-register themselves in `init()`. Adding a provider is
"drop one file in `internal/backend/`, implement `Fetch`, call `Register`."

## Known limitations (being worked on)

- **Exit country can differ from the labelled country.** Many free
  Shadowsocks/Trojan/VMess servers are CDN-fronted (typically Cloudflare),
  or are mislabelled in the source aggregator. We GeoIP the server's
  *advertised* IP, but the actual exit may be elsewhere. We always run the
  exit-IP check after connect and surface the mismatch — but we don't
  auto-retry on it yet, because a "wrong country but fast" server is
  sometimes preferable to a hung "right country" one. **Refining this is
  on the roadmap** — the plan is a server-side health manifest published
  by CI that records each server's *actual* exit country, so the picker
  can stop showing mislabelled entries entirely.
- **Free Shadowsocks/Trojan/VMess servers are slow and short-lived.** The
  bandwidth probe + auto-retry hides most of this, but if every server in
  a country is dead at the same moment, the connect attempt fails clearly
  after 3 tries.
- **No background / daemon mode yet.** Connection is foreground;
  Ctrl-C disconnects. A `--detach` mode is on the roadmap.

## Architecture

```
cmd/                    Cobra commands (connect, list, status, doctor, validate)
internal/backend/       Backend interface + vpngate, riseup, ss-aggregator
internal/proxy/         sing-box installer, parser, runner, outbound generator
internal/openvpn/       OpenVPN locate / install / run
internal/runtools/      Shared subprocess driver (output capture, ready detection)
internal/diagnose/      Pattern matcher: raw engine errors → friendly messages
internal/speedtest/     Post-connect bandwidth probe via Cloudflare
internal/exitcheck/     Post-connect exit-IP / country verification
internal/geoip/         ip-api.com batch lookups + parallel DNS + disk cache
internal/ui/            huh-based interactive country picker
```

Every backend implements:

```go
type Backend interface {
    Name() string
    Fetch(ctx context.Context) ([]Server, error)
}
```

## Roadmap

Tracked in [`DEV/todo.md`](DEV/todo.md) (local; not committed). Highlights:

- [x] OpenVPN + sing-box dispatch
- [x] Real bandwidth probe + auto-retry on slow servers
- [x] Exit-IP verification
- [x] TUIC and Hysteria2 protocols
- [x] Parallel DNS + disk-backed GeoIP cache
- [ ] **BigDataCloud as GeoIP fallback** (next — ip-api.com rate-limit hardening)
- [ ] **Cloudflare WARP** as a global "fastest anonymous tunnel" entry
- [ ] **Failure-quarantine** with exponential backoff (don't keep re-picking dead servers)
- [ ] **Pre-scored manifest in CI** — every server validated + exit-IP-checked every hour, served as a JSON the CLI just downloads. Eliminates per-connect roulette and **fixes the labelled-country accuracy problem above**.

## Credits

This project would not exist without:

- [VPN Gate](https://www.vpngate.net/) — University of Tsukuba
- [Riseup Networks](https://riseup.net/vpn) — anonymous LEAP-based VPN
- [sing-box](https://sing-box.sagernet.org/) — universal proxy engine
- [OpenVPN community](https://openvpn.net/community/) — protocol + client
- The maintainers of every free-config aggregator in `ss-aggregator`'s
  source list (see `internal/backend/ssaggregator.go`)
- [cobra](https://github.com/spf13/cobra) — CLI framework
- [huh](https://github.com/charmbracelet/huh) — interactive forms

## License

TBD — likely MIT or Apache-2.0. Note that OpenVPN and sing-box are
invoked as separate subprocesses (not linked), so their licenses (GPLv2
and GPLv3 respectively) don't restrict `tun0access`'s license choice.
