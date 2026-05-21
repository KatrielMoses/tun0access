package cmd

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether a tun0access tunnel interface is currently up",
	RunE: func(cmd *cobra.Command, args []string) error {
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		var tunnels []net.Interface
		for _, ifc := range ifaces {
			n := strings.ToLower(ifc.Name)
			if ifc.Flags&net.FlagUp == 0 {
				continue
			}
			// Heuristic: openvpn names its adapter "tun0" on Linux, "utunN" on
			// macOS, and uses "TAP-Windows Adapter" / "OpenVPN Wintun" names
			// on Windows.
			if strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "utun") ||
				strings.Contains(n, "openvpn") || strings.Contains(n, "tap-windows") ||
				strings.Contains(n, "wintun") {
				tunnels = append(tunnels, ifc)
			}
		}
		if len(tunnels) == 0 {
			fmt.Println("status: disconnected (no tunnel interface up)")
			return nil
		}
		fmt.Printf("status: connected (%s)\n", runtime.GOOS)
		for _, ifc := range tunnels {
			addrs, _ := ifc.Addrs()
			var ips []string
			for _, a := range addrs {
				ips = append(ips, a.String())
			}
			fmt.Printf("  %s  %s\n", ifc.Name, strings.Join(ips, ", "))
		}
		return nil
	},
}
