// Package ui contains the interactive country picker used by `connect`.
package ui

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/huh"
	"github.com/KatrielMoses/tun0access/internal/backend"
)

// CountryEntry is one row in the picker.
type CountryEntry struct {
	Code        string // ISO-3166 alpha-2
	Name        string // human-readable
	ServerCount int
	BestScore   int64
}

// BuildEntries turns a flat server list into a sorted slice of country
// entries, best-coverage countries first.
func BuildEntries(servers []backend.Server) []CountryEntry {
	byCC := map[string]*CountryEntry{}
	for _, s := range servers {
		cc := s.CountryShort
		if cc == "" {
			continue
		}
		e, ok := byCC[cc]
		if !ok {
			e = &CountryEntry{Code: cc, Name: s.CountryLong}
			byCC[cc] = e
		}
		e.ServerCount++
		if s.Score > e.BestScore {
			e.BestScore = s.Score
		}
	}
	out := make([]CountryEntry, 0, len(byCC))
	for _, e := range byCC {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerCount != out[j].ServerCount {
			return out[i].ServerCount > out[j].ServerCount
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// PickCountry runs an interactive selector and returns the chosen country
// code (e.g. "JP"). Returns "" with a nil error if the user cancels.
func PickCountry(entries []CountryEntry) (string, error) {
	if len(entries) == 0 {
		return "", fmt.Errorf("no countries available")
	}

	opts := make([]huh.Option[string], 0, len(entries))
	for _, e := range entries {
		label := fmt.Sprintf("%s  %s  (%d server", flag(e.Code), e.Name, e.ServerCount)
		if e.ServerCount != 1 {
			label += "s"
		}
		label += ")"
		opts = append(opts, huh.NewOption(label, e.Code))
	}

	var chosen string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Choose a country to tunnel through").
				Description("Up/down to move, / to filter, enter to connect, esc to cancel").
				Options(opts...).
				Value(&chosen),
		),
	).WithShowHelp(true)

	if err := form.Run(); err != nil {
		// huh returns ErrUserAborted on Ctrl-C / Esc — treat as a clean cancel.
		if err == huh.ErrUserAborted {
			return "", nil
		}
		return "", err
	}
	return chosen, nil
}

// flag converts an ISO-3166 alpha-2 code into a regional-indicator emoji
// sequence (e.g. "JP" -> 🇯🇵). Returns the code itself if it isn't 2 letters.
func flag(cc string) string {
	if len(cc) != 2 {
		return cc
	}
	const base = 0x1F1E6 - 'A'
	r1 := rune(cc[0]) + base
	r2 := rune(cc[1]) + base
	return string([]rune{r1, r2})
}
