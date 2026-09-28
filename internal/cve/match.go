package cve

import (
	"embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sysrqio/crafttrace/internal/sbom"
)

//go:embed fixtures/cve-db.json
var fixtureFS embed.FS

// Severity levels ordered for comparison.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding is a matched vulnerability for a component.
type Finding struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Component  string `json:"component"`
	Version    string `json:"version"`
	FixedIn    string `json:"fixed_in,omitempty"`
	Source     string `json:"source"`
}

// Summary aggregates findings by severity.
type Summary struct {
	Findings []Finding         `json:"findings"`
	Counts   map[string]int    `json:"counts"`
}

type fixtureDB struct {
	Entries []fixtureEntry `json:"entries"`
}

type fixtureEntry struct {
	Package  string `json:"package"`
	Version  string `json:"version"`
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	FixedIn  string `json:"fixed_in"`
}

// MatchComponents uses embedded fixture DB; optionally grype if on PATH.
func MatchComponents(components []sbom.Component, preferGrype bool) (Summary, error) {
	if preferGrype {
		if path, err := exec.LookPath("grype"); err == nil && path != "" {
			if s, err := matchGrype(components); err == nil {
				return s, nil
			}
		}
	}
	return matchFixture(components)
}

func matchFixture(components []sbom.Component) (Summary, error) {
	data, err := fixtureFS.ReadFile("fixtures/cve-db.json")
	if err != nil {
		return Summary{}, err
	}
	var db fixtureDB
	if err := json.Unmarshal(data, &db); err != nil {
		return Summary{}, err
	}

	index := make(map[string][]fixtureEntry)
	for _, e := range db.Entries {
		key := strings.ToLower(e.Package) + "@" + e.Version
		index[key] = append(index[key], e)
	}

	summary := Summary{Counts: map[string]int{
		SeverityLow: 0, SeverityMedium: 0, SeverityHigh: 0, SeverityCritical: 0,
	}}

	for _, c := range components {
		key := strings.ToLower(c.Name) + "@" + c.Version
		entries, ok := index[key]
		if !ok {
			// also match wildcard version in fixture
			keyAny := strings.ToLower(c.Name) + "@*"
			entries = index[keyAny]
		}
		for _, e := range entries {
			f := Finding{
				ID:        e.CVE,
				Severity:  normalizeSeverity(e.Severity),
				Component: c.Name,
				Version:   c.Version,
				FixedIn:   e.FixedIn,
				Source:    "embedded-fixture",
			}
			summary.Findings = append(summary.Findings, f)
			summary.Counts[f.Severity]++
		}
	}
	return summary, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return strings.ToLower(s)
	default:
		return SeverityLow
	}
}

// ExceedsFailOn returns true if any finding meets or exceeds the threshold.
func (s Summary) ExceedsFailOn(threshold string) bool {
	order := map[string]int{
		SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
	}
	min := order[normalizeSeverity(threshold)]
	if min == 0 {
		min = order[SeverityCritical]
	}
	for sev, count := range s.Counts {
		if count > 0 && order[sev] >= min {
			return true
		}
	}
	return false
}

func matchGrype(components []sbom.Component) (Summary, error) {
	// MVP: grype integration stub — fall back if not implemented
	return Summary{}, fmt.Errorf("grype integration not configured")
}
