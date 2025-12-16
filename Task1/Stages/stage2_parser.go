package main

import (
	"fmt"
	"os"
)

// Stage 2 - بيقرأ محتوى الملف و يبعته في channel
func Stage2Parser(in <-chan string, out chan<- string) {
	for filename := range in {
		data, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("❌ Error reading file: %v\n", err)
			close(out)
			return
		}
		out <- string(data)
	}
	close(out)
}
