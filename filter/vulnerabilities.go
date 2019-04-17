package filter

// Print prints per-package details
func (vs *Vulnerabilities) Print() {
	for _, v := range *vs {
		v.PrintPackageNameVersion()
	}
}

// UniquePackages returns true/false if package already added
func (vs *Vulnerabilities) UniquePackages() Vulnerabilities {
	var newVs Vulnerabilities
	pkgs := map[string]Vulnerability{}
	for _, v := range *vs {
		if _, ok := pkgs[v.Name]; !ok {
			pkgs[v.Name] = v
			newVs = append(newVs, v)
		}
	}
	return newVs
}

// GetFixables returns a set of issues that can be resolved
func (vs *Vulnerabilities) GetFixables() Vulnerabilities {
	var res Vulnerabilities
	for _, v := range *vs {
		if v.IsPatchable == true || v.IsUpgradable == true {
			res = append(res, v)
		} else {
			if _, ok := v.NearestFixedInVersion.(string); ok {
				res = append(res, v)
			}
		}
	}
	return res.UniquePackages()
}
