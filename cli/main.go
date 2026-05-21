package main

import (
	"fmt"
	"os"

	"github.com/tun0access/tun0access/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
