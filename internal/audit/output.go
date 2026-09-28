package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/sysrqio/crafttrace/internal/cve"
)

// WriteOutput renders the report to w (and optionally a file).
func WriteOutput(w io.Writer, r Report, format string, noColor bool) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "cyclonedx-json":
		data, err := r.SBOM.ToJSON()
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	case "sarif":
		return writeSARIF(w, r)
	case "table", "":
		return writeTable(w, r, noColor)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeTable(w io.Writer, r Report, noColor bool) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Target\t%s\n", r.Target)
	fmt.Fprintf(tw, "Components\t%d\n", len(r.SBOM.Components))
	fmt.Fprintf(tw, "CRA score\t%d/%d (%.0f%%)\n", r.Score.Total, r.Score.Max, r.Score.Percent)
	fmt.Fprintln(tw, "\nCVE summary")
	for _, sev := range []string{cve.SeverityCritical, cve.SeverityHigh, cve.SeverityMedium, cve.SeverityLow} {
		fmt.Fprintf(tw, "  %s\t%d\n", sev, r.CVE.Counts[sev])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(r.CVE.Findings) > 0 {
		fmt.Fprintln(w, "\nFindings:")
		for _, f := range r.CVE.Findings {
			line := fmt.Sprintf("  [%s] %s %s@%s (%s)", strings.ToUpper(f.Severity), f.ID, f.Component, f.Version, f.Source)
			if !noColor {
				line = colorSeverity(f.Severity, line)
			}
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w, "\nScore breakdown:")
	for _, item := range r.Score.Breakdown {
		status := "no"
		if item.Met {
			status = "yes"
		}
		fmt.Fprintf(w, "  %s: %d/%d (%s) — %s\n", item.ID, item.Points, item.Max, status, item.Message)
	}
	return nil
}

func colorSeverity(sev, line string) string {
	switch sev {
	case cve.SeverityCritical:
		return "\033[31m" + line + "\033[0m"
	case cve.SeverityHigh:
		return "\033[33m" + line + "\033[0m"
	default:
		return line
	}
}

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func writeSARIF(w io.Writer, r Report) error {
	results := make([]sarifResult, 0, len(r.CVE.Findings))
	for _, f := range r.CVE.Findings {
		results = append(results, sarifResult{
			RuleID: f.ID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s@%s: %s", f.Component, f.Version, f.ID),
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Component},
				},
			}},
		})
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{Name: "crafttrace", Version: "0.1.0"}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(sev string) string {
	switch sev {
	case cve.SeverityCritical, cve.SeverityHigh:
		return "error"
	case cve.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteToFile optionally duplicates output.
func WriteToFile(path string, r Report, format string) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteOutput(f, r, format, true)
}
