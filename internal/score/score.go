package score

import (
	"github.com/sysrqio/crafttrace/internal/cve"
	"github.com/sysrqio/crafttrace/internal/sbom"
)

const MaxScore = 100

// Result is the CRA readiness score breakdown.
type Result struct {
	Total       int      `json:"total"`
	Max         int      `json:"max"`
	Percent     float64  `json:"percent"`
	Breakdown   []Item   `json:"breakdown"`
	Licenses    []string `json:"licenses,omitempty"`
}

type Item struct {
	ID      string `json:"id"`
	Points  int    `json:"points"`
	Max     int    `json:"max"`
	Met     bool   `json:"met"`
	Message string `json:"message"`
}

// Compute derives a simple CRA readiness score from audit artifacts.
func Compute(bom *sbom.BOM, summary cve.Summary, scanCompleted bool) Result {
	items := []Item{
		{
			ID: "sbom-generated", Points: 0, Max: 25,
			Message: "SBOM inventory produced",
		},
		{
			ID: "scan-completed", Points: 0, Max: 25,
			Message: "Vulnerability scan completed",
		},
		{
			ID: "no-critical-unmitigated", Points: 0, Max: 30,
			Message: "No critical unmitigated vulnerabilities",
		},
		{
			ID: "license-inventory", Points: 0, Max: 20,
			Message: "License inventory captured",
		},
	}

	if bom != nil && len(bom.Components) > 0 {
		items[0].Points = items[0].Max
		items[0].Met = true
	}
	if scanCompleted {
		items[1].Points = items[1].Max
		items[1].Met = true
	}
	critical := summary.Counts[cve.SeverityCritical]
	if critical == 0 {
		items[2].Points = items[2].Max
		items[2].Met = true
	} else {
		items[2].Message = "Critical vulnerabilities present — remediate or document mitigations"
	}

	licenses := []string{}
	if bom != nil {
		licenses = bom.LicenseInventory()
	}
	if len(licenses) > 0 {
		items[3].Points = items[3].Max
		items[3].Met = true
	} else if bom != nil && len(bom.Components) > 0 {
		// partial credit if components exist but licenses unknown
		items[3].Points = 10
		items[3].Message = "Partial license inventory (some unknown)"
	}

	total := 0
	max := 0
	for _, it := range items {
		total += it.Points
		max += it.Max
	}
	pct := 0.0
	if max > 0 {
		pct = float64(total) / float64(max) * 100
	}

	return Result{
		Total:     total,
		Max:       max,
		Percent:   pct,
		Breakdown: items,
		Licenses:  licenses,
	}
}
