package filter

// OnlyWithParticularSeverity is for filtering out vulnerabilities with high severity
func (sr *ScanResult) OnlyWithParticularSeverity(severity string) Vulnerabilities {
	var res Vulnerabilities
	for _, v := range sr.Vulnerabilities {
		if v.Severity == severity {
			res = append(res, v)
		}
	}
	return res
}

// GetIssuesWIthTheFollowingSeverity prints issues with high severity
func (sr *ScanResult) GetIssuesWIthTheFollowingSeverity(severity string) Vulnerabilities {
	issues := sr.OnlyWithParticularSeverity(severity)
	return issues.GetFixables()
}
