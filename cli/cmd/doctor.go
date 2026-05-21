package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/KatrielMoses/tun0access/internal/backend"
	"github.com/KatrielMoses/tun0access/internal/openvpn"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose the local environment (openvpn install, backends, connectivity)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("OS:        %s/%s\n", runtime.GOOS, runtime.GOARCH)

		if p := openvpn.Locate(); p != "" {
			fmt.Println("openvpn:   ✓", p)
			if err := openvpn.Verify(cmd.Context(), p); err != nil {
				fmt.Println("  verify failed:", err)
			}
		} else {
			fmt.Println("openvpn:   ✗ not found (run `tun0access connect` to auto-install)")
		}

		fmt.Println("backends:")
		for _, b := range backend.All() {
			servers, err := b.Fetch(cmd.Context())
			if err != nil {
				fmt.Printf("  %-16s ✗ %v\n", b.Name(), err)
				continue
			}
			fmt.Printf("  %-16s ✓ %d servers\n", b.Name(), len(servers))
		}
		return nil
	},
}
