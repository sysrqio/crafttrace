package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const FileName = "crafttrace.yaml"

// DefaultPath returns the user config path (~/.config/crafttrace/crafttrace.yaml).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "crafttrace", FileName), nil
}

// SampleYAML is a commented starter config for `crafttrace config`.
const SampleYAML = `# crafttrace configuration (optional)
# fail_on: critical   # critical|high|medium|low
# min_score: 0
# output: table
# prefer_grype: false
`

// ShowInfo prints default path and sample.
func ShowInfo() (string, error) {
	p, err := DefaultPath()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Default config path: %s\n\nSample:\n%s", p, SampleYAML), nil
}
