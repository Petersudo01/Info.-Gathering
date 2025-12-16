package main

import (
	"regexp"
	"strings"
)

// Stage 4 - detect frameworks and their versions from the code string
// in <-chan []Finding : receives findings from analyzer
// code string         : full source code (from Stage2Parser)
// out chan<- Report   : send the final Report
// filename string     : file name to include in Report
func normalizeFrameworkName(name string) string {
	switch strings.ToLower(name) {
	case "react":
		return "React"
	case "vue":
		return "Vue"
	case "next":
		return "Next.js"
	case "angular":
		return "Angular"
	case "express":
		return "Express"
	default:
		return name
	}
}

func Stage4Framework(in <-chan []Finding, code string, out chan<- Report, filename string) {
	findings := <-in

	frameworkPatterns := map[string]*regexp.Regexp{
		"React":   regexp.MustCompile(`react(?:@|[/-]v?)(\d+\.\d+\.\d+)?`),
		"Angular": regexp.MustCompile(`@angular(?:[/-]v?)(\d+\.\d+\.\d+)?`),
		"Vue":     regexp.MustCompile(`vue(?:@|[/-]v?)(\d+\.\d+\.\d+)?`),
		"Next.js": regexp.MustCompile(`next(?:@|[/-]v?)(\d+\.\d+\.\d+)?`),
		"Express": regexp.MustCompile(`express(?:@|[/-]v?)(\d+\.\d+\.\d+)?`),
	}

	frameworkMap := make(map[string]FrameworkInfo)
	for name, re := range frameworkPatterns {
		if matches := re.FindAllStringSubmatch(code, -1); matches != nil {
			for _, m := range matches {
				normName := normalizeFrameworkName(name)
				version := ""
				if len(m) > 1 {
					version = m[1]
				}
				// add or update only if better version
				if existing, ok := frameworkMap[normName]; ok {
					if version != "" && existing.Version == "" {
						existing.Version = version
						frameworkMap[normName] = existing
					}
				} else {
					frameworkMap[normName] = FrameworkInfo{Name: normName, Version: version}
				}
			}
		}
	}

	// convert map to slice
	var frameworks []FrameworkInfo
	for _, fw := range frameworkMap {
		frameworks = append(frameworks, fw)
	}

	report := Report{
		File:              filename,
		DangerousFindings: findings,
		Frameworks:        frameworks,
	}
	out <- report
	close(out)
}
