package main

// structs المشتركة بين كل الـ stages

// Finding => تمثل نتيجة تحليل زي eval() أو API key
type Finding struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
}

// FrameworkInfo => بتخزن معلومات عن الفريمورك
type FrameworkInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Report => التجميع النهائي لكل النتائج
type Report struct {
	File              string          `json:"file"`
	DangerousFindings []Finding       `json:"dangerous_functions"`
	Secrets           []Finding       `json:"secrets"`
	Frameworks        []FrameworkInfo `json:"frameworks"`
}
