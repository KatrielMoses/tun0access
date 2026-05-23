package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tun0access",
	Short: "tun0access — one-command free VPN access across many countries",
	Long: `tun0access is a cross-platform CLI that aggregates free VPN and proxy
servers from public sources (VPN Gate, Riseup, Cloudflare WARP, and a pool of
~3,900 Shadowsocks / VMess / VLESS / Trojan / TUIC / Hysteria2 endpoints
from public config repos). Pick a country, hit enter, and you're on tun0.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(doctorCmd)
}
