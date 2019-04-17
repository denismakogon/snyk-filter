package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/denismakogon/snyk-filter/config"
)

// Vulnerability struct
type Vulnerability struct {
	Severity              string      `json:"severity"`
	IsUpgradable          bool        `json:"isUpgradable"`
	IsPatchable           bool        `json:"isPatchable"`
	Name                  string      `json:"name"`
	NearestFixedInVersion interface{} `json:"nearestFixedInVersion"`
}

// PrintPackageNameVersion prints fixable package name and version
func (v *Vulnerability) PrintPackageNameVersion() {
	fmt.Printf("%v==%s\n", v.Name, v.NearestFixedInVersion)
}

// Vulnerabilities represents a set of vulnerabilities
type Vulnerabilities []Vulnerability

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

// ScanResult is a resulting object of Slyk CLI tool
type ScanResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         string          `json:"summary"`
	DockerImage     string          `json:"path"`
	Ok              bool            `json:"ok"`
}

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

func main() {

	severity := flag.String("severity", "all", "the severity to filter issues by, values: all/final/high/medium/low")
	version := flag.Bool("version", true, "returns CLI tool version")
	flag.Parse()

	if *version {
		fmt.Println(config.Version)
		return
	}

	var res ScanResult
	err := json.NewDecoder(os.Stdin).Decode(&res)
	if err != nil {
		log.Fatal(err.Error())
	}
	if !res.Ok {
		if *severity == "all" {
			fmt.Println("-----------------------------------------")
			fmt.Println("Low severity issues:")
			low := res.GetIssuesWIthTheFollowingSeverity("low")
			low.Print()
			fmt.Println("-----------------------------------------")
			fmt.Println("Medium severity issues:")
			medium := res.GetIssuesWIthTheFollowingSeverity("medium")
			medium.Print()
			fmt.Println("-----------------------------------------")
			fmt.Println("High severity issues:")
			high := res.GetIssuesWIthTheFollowingSeverity("high")
			high.Print()
			fmt.Println("-----------------------------------------")
		}

		if *severity == "final" {
			var uniqueVs Vulnerabilities
			low := res.GetIssuesWIthTheFollowingSeverity("low")
			medium := res.GetIssuesWIthTheFollowingSeverity("medium")
			high := res.GetIssuesWIthTheFollowingSeverity("high")
			uniqueVs = append(uniqueVs, low...)
			uniqueVs = append(uniqueVs, medium...)
			uniqueVs = append(uniqueVs, high...)

			final := uniqueVs.UniquePackages()
			fmt.Println("-----------------------------------------")
			fmt.Println("Final packages to update:")
			final.Print()
			fmt.Println("-----------------------------------------")
		}

		if *severity == "low" {
			fmt.Println("-----------------------------------------")
			fmt.Println("Low severity issues:")
			low := res.GetIssuesWIthTheFollowingSeverity("low")
			low.Print()
			fmt.Println("-----------------------------------------")
		}
		if *severity == "medium" {
			fmt.Println("-----------------------------------------")
			fmt.Println("Medium severity issues:")
			medium := res.GetIssuesWIthTheFollowingSeverity("medium")
			medium.Print()
			fmt.Println("-----------------------------------------")
		}
		if *severity == "high" {
			fmt.Println("-----------------------------------------")
			fmt.Println("High severity issues:")
			high := res.GetIssuesWIthTheFollowingSeverity("high")
			high.Print()
			fmt.Println("-----------------------------------------")
		}
	}
}
