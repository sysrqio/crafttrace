package sbom

import (
	"encoding/json"
	"fmt"
	"time"
)

const SpecVersion = "1.5"

// BOM represents a minimal CycloneDX-like SBOM for MVP output.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata,omitempty"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string `json:"timestamp,omitempty"`
	Tools     []Tool `json:"tools,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type Component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type License struct {
	License LicenseChoice `json:"license"`
}

type LicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// NewBOM creates an empty BOM with crafttrace metadata.
func NewBOM(components []Component) *BOM {
	return &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: SpecVersion,
		Version:     1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{{
				Vendor:  "sysrq.io",
				Name:    "crafttrace",
				Version: Version(),
			}},
		},
		Components: components,
	}
}

// ParseCycloneDX reads CycloneDX JSON from bytes.
func ParseCycloneDX(data []byte) (*BOM, error) {
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parse cyclonedx json: %w", err)
	}
	if bom.BOMFormat != "" && bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("unsupported bom format %q", bom.BOMFormat)
	}
	return &bom, nil
}

// ToJSON marshals the BOM.
func (b *BOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// LicenseInventory returns distinct license IDs/names found in components.
func (b *BOM) LicenseInventory() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, c := range b.Components {
		for _, l := range c.Licenses {
			id := l.License.ID
			if id == "" {
				id = l.License.Name
			}
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
