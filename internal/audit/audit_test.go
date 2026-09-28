package audit_test

import (
	"bytes"
	"path/filepath"
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
