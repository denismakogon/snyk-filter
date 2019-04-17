package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/denismakogon/snyk-filter/config"
	"github.com/denismakogon/snyk-filter/filter"
)

func main() {

	severity := flag.String("severity", "all", "the severity to filter issues by, values: all/high/medium/low")
	version := flag.Bool("version", false, "returns CLI tool version")
	flag.Parse()

	if *version {
		fmt.Println(config.Version)
		return
	}

	var res filter.ScanResult
	err := json.NewDecoder(os.Stdin).Decode(&res)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !res.Ok {

		if *severity == "all" {
			var uniqueVs filter.Vulnerabilities
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
			if len(final) > 0 {
				log.Fatalf("Failed. %v vulnerabilities found.", len(final))
			}
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
