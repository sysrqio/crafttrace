package manifest_test

import (
	"path/filepath"
	"testing"

	"github.com/sysrqio/crafttrace/internal/manifest"
)

func TestScanDirGoMod(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "manifests")
	comps, err := manifest.ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) < 2 {
		t.Fatalf("expected at least 2 components, got %d", len(comps))
	}
}

func TestScanRequirements(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "manifests", "requirements.txt")
	comps, err := manifest.ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(comps))
	}
}
