package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGreen  = "\033[32m"
)

// Stage 5 - بيطبع النتائج و يحفظ JSON
func Stage5Reporter(in <-chan Report, done chan<- struct{}) {
	report := <-in

	fmt.Printf("\n📊 %sAnalysis results for file: %s%s\n", ColorCyan, report.File, ColorReset)

	for _, f := range report.DangerousFindings {
		col := ColorYellow
		icon := "⚠️"
		if f.Severity == "high" {
			col = ColorRed
		}
		fmt.Printf("%s[%s] %s - Line %d%s\n", col, icon, f.Detail, f.Line, ColorReset)
	}

	for _, fw := range report.Frameworks {
		fmt.Printf("%s[⚙️ FRAMEWORK] %s v%s%s\n", ColorCyan, fw.Name, fw.Version, ColorReset)
	}

	// save JSON
	data, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile("report.json", data, 0644)
	fmt.Printf("\n%s✅ Report saved as report.json%s\n", ColorGreen, ColorReset)

	done <- struct{}{}
}
