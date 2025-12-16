package main

import "fmt"

// Stage 1 - بياخد اسم الملف و يبعتو في الـ channel
func Stage1Scanner(filename string, out chan<- string) {
	fmt.Printf("🚀 Starting analysis for file: %s\n", filename)
	out <- filename
	close(out)
}
