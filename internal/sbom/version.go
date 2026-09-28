package sbom

// versionString is set via -ldflags at build time.
var versionString = "0.1.0-dev"

// Version returns the crafttrace version.
func Version() string {
	return versionString
}
