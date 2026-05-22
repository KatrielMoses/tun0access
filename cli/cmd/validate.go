package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KatrielMoses/tun0access/internal/backend"
	"github.com/KatrielMoses/tun0access/internal/proxy"
	"github.com/spf13/cobra"
)

// validate is a hidden-from-help integration test: it pulls real servers
// from every backend, generates the sing-box config for each, and runs the
// installed sing-box binary's `check` subcommand on the generated config.
// Failures are aggregated by their last-line error so we can see which
// classes of server we should filter out at parse time.
var validateCmd = &cobra.Command{
	Use:    "validate",
	Hidden: true,
	Short:  "Generate the sing-box config for every server and validate it locally",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
		defer cancel()

		bin, err := proxy.EnsureSingBox(ctx)
		if err != nil {
			return fmt.Errorf("sing-box install: %w", err)
		}
		fmt.Println("Using:", bin)

		fmt.Println("Fetching all backends…")
		servers, errs := backend.FetchAll(ctx)
		for _, e := range errs {
			fmt.Println("  warn:", e)
		}
		fmt.Printf("Got %d total servers\n\n", len(servers))

		// Only protocols we route to sing-box.
		ok, fail := 0, 0
		failByErr := map[string]int{}
		failExamples := map[string]string{}

		for i, s := range servers {
			switch s.Protocol {
			case "shadowsocks", "vmess", "vless", "trojan":
			default:
				continue
			}

			var out proxy.Outbound
			if err := json.Unmarshal(s.Config, &out); err != nil {
				fail++
				key := "json: " + err.Error()
				failByErr[key]++
				continue
			}

			cfgBytes, err := proxy.BuildConfigForValidate(&out)
			if err != nil {
				fail++
				key := "build: " + err.Error()
				failByErr[key]++
				if failExamples[key] == "" {
					failExamples[key] = s.ID
				}
				continue
			}

			// Write to a unique temp file then run sing-box check.
			tmp, err := os.CreateTemp("", fmt.Sprintf("validate-%d-*.json", i))
			if err != nil {
				return err
			}
			tmp.Write(cfgBytes)
			tmp.Close()

			out2, runErr := exec.CommandContext(ctx, bin, "check", "-c", tmp.Name()).CombinedOutput()
			os.Remove(tmp.Name())

			if runErr == nil {
				ok++
				continue
			}
			fail++
			// The error message comes from sing-box; collapse to the last
			// meaningful line.
			msg := lastLine(string(out2))
			msg = stripVariablePart(msg)
			failByErr[msg]++
			if failExamples[msg] == "" {
				failExamples[msg] = fmt.Sprintf("%s [%s]", s.ID, s.Protocol)
			}
		}

		fmt.Printf("OK:   %d\nFAIL: %d\n\n", ok, fail)

		type pair struct {
			err string
			n   int
		}
		var pairs []pair
		for k, v := range failByErr {
			pairs = append(pairs, pair{k, v})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].n > pairs[j].n })

		fmt.Println("Failure categories (count, error, example):")
		for _, p := range pairs {
			fmt.Printf("  %4d  %s\n        example: %s\n", p.n, p.err, failExamples[p.err])
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(validateCmd) }

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		// Strip ANSI colour codes and timestamps.
		if idx := strings.Index(l, "FATAL["); idx >= 0 {
			l = l[idx:]
		}
		return l
	}
	return ""
}

// stripVariablePart collapses error lines that contain things like
// `outbound[0]` or specific UUIDs so we count failures of the same class.
func stripVariablePart(s string) string {
	// Drop bracketed indices like [0], [12], etc.
	out := []rune{}
	skip := false
	for _, r := range s {
		if r == '[' {
			skip = true
			continue
		}
		if r == ']' {
			skip = false
			continue
		}
		if !skip {
			out = append(out, r)
		}
	}
	return string(out)
}

// suppress unused-import warnings if we ever rip out the temp file path
var _ = filepath.Join
