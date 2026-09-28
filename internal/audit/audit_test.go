package audit_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysrqio/crafttrace/internal/audit"
)

func TestAuditDirOffline(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "manifests")
	report, err := audit.Run(audit.Options{Target: "dir:" + root})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SBOM.Components) == 0 {
		t.Fatal("expected components")
	}
	if report.CVE.Counts["high"]+report.CVE.Counts["critical"] == 0 {
		t.Fatal("expected CVE matches from fixtures")
	}
}

func TestAuditSBOM(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "sbom", "sample.cdx.json")
	report, err := audit.Run(audit.Options{Target: "sbom:" + path})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SBOM.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(report.SBOM.Components))
	}
	if report.CVE.Counts["high"] != 1 {
		t.Fatalf("expected 1 high CVE, got counts %#v", report.CVE.Counts)
	}
	if len(report.CVE.Findings) != 1 || report.CVE.Findings[0].ID != "CVE-2021-23337" {
		t.Fatalf("unexpected findings: %#v", report.CVE.Findings)
	}
}

func TestAuditFileManifest(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "manifests", "requirements.txt")
	report, err := audit.Run(audit.Options{Target: "file:" + path})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(report.Target, "file:") {
		t.Fatalf("target = %q", report.Target)
	}
	if len(report.SBOM.Components) != 2 {
		t.Fatalf("expected 2 components from requirements.txt, got %d", len(report.SBOM.Components))
	}
	if report.CVE.Counts["critical"] != 1 {
		t.Fatalf("expected critical CVE for pillow fixture, got %#v", report.CVE.Counts)
	}
}

func TestPolicyViolationMinScore(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "sbom", "sample.cdx.json")
	report, err := audit.Run(audit.Options{Target: "sbom:" + path})
	if err != nil {
		t.Fatal(err)
	}
	if report.Score.Total != 100 {
		t.Fatalf("expected score 100 from sbom fixture, got %d", report.Score.Total)
	}
	if !audit.PolicyViolation(report, "critical", 101) {
		t.Fatal("expected min-score 101 violation")
	}
	if audit.PolicyViolation(report, "critical", 100) {
		t.Fatal("score 100 should satisfy min-score 100")
	}
}

func TestPolicyViolation(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "manifests")
	report, err := audit.Run(audit.Options{Target: "dir:" + root})
	if err != nil {
		t.Fatal(err)
	}
	if !audit.PolicyViolation(report, "critical", 0) {
		t.Fatal("expected policy violation for critical CVE in fixtures")
	}
}

func TestJSONOutput(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "manifests")
	report, err := audit.Run(audit.Options{Target: "dir:" + root})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := audit.WriteOutput(&buf, report, "json", true); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty json output")
	}
}
