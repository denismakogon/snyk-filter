package filter

import "strings"

// CWEtoString turns a list of strings to a string
func (vi *VulnerabilityIdentifier) CWEtoString() string {
	return strings.Join(vi.CWE, " | ")
}

// CVEtoString turns a list of strings to a string
func (vi *VulnerabilityIdentifier) CVEtoString() string {
	return strings.Join(vi.CVE, " | ")
}
