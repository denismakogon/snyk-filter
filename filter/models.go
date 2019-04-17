package filter

// VulnerabilityIdentifier represents actual secyrity issue references
// - CWE and CVE
type VulnerabilityIdentifier struct {
	CWE []string `json:"CWE"`
	CVE []string `json:"CVE"`
}

// Vulnerability struct
type Vulnerability struct {
	Severity              string                  `json:"severity"`
	IsUpgradable          bool                    `json:"isUpgradable"`
	IsPatchable           bool                    `json:"isPatchable"`
	Name                  string                  `json:"name"`
	NearestFixedInVersion interface{}             `json:"nearestFixedInVersion"`
	Identifiers           VulnerabilityIdentifier `json:"identifiers"`
}

// Vulnerabilities represents a set of vulnerabilities
type Vulnerabilities []Vulnerability

// ScanResult is a resulting object of Slyk CLI tool
type ScanResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         string          `json:"summary"`
	DockerImage     string          `json:"path"`
	Ok              bool            `json:"ok"`
}
