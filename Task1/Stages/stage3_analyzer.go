package main

import (
	"bufio"
	"fmt"
	"strings"
)

// Stage3Analyzer بيحلل كود الجافاسكربت ويكشف الدوال الخطيرة والبيانات الحساسة
func Stage3Analyzer(in <-chan string, out chan<- []Finding) {
	fmt.Println("🔍 Stage3 Analyzer working...")

	var findings []Finding

	dangerous := []string{"eval", "Function", "exec", "setTimeout", "setInterval"}
	sensitive := []string{"api_key", "token", "password", "secret", "AWS_ACCESS_KEY", "PRIVATE_KEY"}

	for code := range in {
		scanner := bufio.NewScanner(strings.NewReader(code))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Dangerous functions
			for _, fn := range dangerous {
				if strings.Contains(line, fn+"(") {
					findings = append(findings, Finding{
						Type:     "Dangerous Function",
						Detail:   fn,
						Line:     lineNum,
						Severity: "High",
					})
				}
			}

			// Sensitive data
			for _, s := range sensitive {
				if strings.Contains(strings.ToLower(line), strings.ToLower(s)) {
					findings = append(findings, Finding{
						Type:     "Sensitive Data",
						Detail:   s,
						Line:     lineNum,
						Severity: "Medium",
					})
				}
			}
		}
	}

	out <- findings
	close(out)
}
