package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tun0access/tun0access/internal/backend"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available countries and the number of servers in each",
	RunE: func(cmd *cobra.Command, args []string) error {
		servers, errs := backend.FetchAll(cmd.Context())
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "warning:", e)
		}
		if len(servers) == 0 {
			return fmt.Errorf("no servers available")
		}
		grouped := backend.GroupByCountry(servers)

		type row struct {
			cc, name string
			count    int
		}
		var rows []row
		for cc, pool := range grouped {
			rows = append(rows, row{cc: cc, name: pool[0].CountryLong, count: len(pool)})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CODE\tCOUNTRY\tSERVERS")
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%d\n", r.cc, r.name, r.count)
		}
		return w.Flush()
	},
}
