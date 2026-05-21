# tun0access

> One command, free VPN access, many countries. Cross-platform CLI for
> Windows, macOS, and Linux.

`tun0access` is a thin orchestrator over existing free open-source VPN
backends. It fetches their current server lists, lets you pick a country
interactively, and hands the chosen config to a local `openvpn` process.

```
$ tun0access connect
• Checking for openvpn…
  found: C:\Program Files\OpenVPN\bin\openvpn.exe
• Fetching server list…
  got 97 servers across 10 countries
┌─ Choose a country to tunnel through ───────────────────────┐
│ > 🇯🇵  Japan               (46 servers)                     │
│   🇰🇷  Korea, Republic of  (24 servers)                     │
│   🇷🇺  Russian Federation  (16 servers)                     │
│   🇹🇭  Thailand             (4 servers)                     │
│   …                                                         │
└─────────────────────────────────────────────────────────────┘
```

## Status

Working MVP backed by [VPN Gate](https://www.vpngate.net/) (University of
Tsukuba's free public relay pool). The plug-in interface is in place; see
`internal/backend/protonvpn.go` for the next backend to wire up.

## Install

```sh
# from source (requires Go 1.25+)
cd cli && go build -o tun0access .
```

Binaries via `go install`/Releases coming once the module path is finalized.

`tun0access` needs the OpenVPN community client. It will offer to install it
on first run via:

| OS      | Installer                                       |
|---------|-------------------------------------------------|
| Windows | `winget install OpenVPNTechnologies.OpenVPN`    |
| macOS   | `brew install openvpn`                          |
| Linux   | `apt`/`dnf`/`pacman`/`zypper`/`apk` (autodetected) |

## Usage

```sh
tun0access connect          # interactive country picker
tun0access connect JP       # pin to Japan, pick best server
tun0access list             # show country / server-count table
tun0access status           # is a tunnel adapter currently up?
tun0access doctor           # diagnose openvpn + backend health
```

Connection runs in the foreground. `Ctrl-C` to disconnect.

> On Linux/macOS the tool re-execs `openvpn` under `sudo` because creating a
> tun device requires root. On Windows, the OpenVPN driver requires the
> shell to be elevated — run from an Administrator prompt.

## Architecture

```
cmd/                Cobra commands (connect, list, status, doctor)
internal/backend/   Backend interface + VPN Gate impl + ProtonVPN stub
internal/openvpn/   Locate / install / run the openvpn binary
internal/ui/        huh-based interactive country picker
```

Every backend implements:

```go
type Backend interface {
    Name() string
    Fetch(ctx context.Context) ([]Server, error)
}
```

Backends register themselves in `init()` and are queried concurrently by
`backend.FetchAll`. To add a provider, drop a new file in `internal/backend/`,
implement `Fetch`, and call `Register`.

## Roadmap

- [ ] Wire up ProtonVPN free tier (5 countries, reliable)
- [ ] Wire up VPNBook OpenVPN configs (broader country coverage)
- [ ] Daemon / `--detach` mode with `tun0access disconnect`
- [ ] WireGuard support where backends expose it
- [ ] Server health-check (TCP probe before handing config to openvpn)
- [ ] Telemetry-free per-server latency measurement

## Credits

This project would not exist without:
- [VPN Gate](https://www.vpngate.net/) — University of Tsukuba
- [OpenVPN community](https://openvpn.net/community/) — protocol + client
- [cobra](https://github.com/spf13/cobra) — CLI framework
- [huh](https://github.com/charmbracelet/huh) — interactive forms

## License

TBD — likely MIT or Apache-2.0. Note the OpenVPN binary itself is GPLv2;
`tun0access` only invokes it as a separate process, so the projects are
license-compatible.
