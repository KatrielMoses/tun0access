package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/KatrielMoses/tun0access/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// ErrSilent means the command already printed a user-facing message;
		// we just need to exit non-zero.
		if !errors.Is(err, cmd.ErrSilent) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}
