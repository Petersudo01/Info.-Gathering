package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("❌ Usage: go run . <filename.js>")
		return
	}

	filename := os.Args[1]

	// Channels for each stage
	stage1 := make(chan string)
	stage2 := make(chan string)
	stage3 := make(chan []Finding)
	stage4 := make(chan Report)
	done := make(chan struct{})

	// Stage 1: Scanner
	go Stage1Scanner(filename, stage1)

	// Stage 2: Parser
	go Stage2Parser(stage1, stage2)

	// Wait for Stage2Parser to finish and get the code
	var code string
	for c := range stage2 {
		code = c
	}

	// Stage 3: Analyzer
	codeChan := make(chan string)       // channel to feed code to analyzer
	go Stage3Analyzer(codeChan, stage3) // run analyzer
	codeChan <- code                    // send code string
	close(codeChan)                     // signal end of input

	// Stage 4: Framework detector
	go Stage4Framework(stage3, code, stage4, filename)

	// Stage 5: Reporter
	go Stage5Reporter(stage4, done)

	// Wait until reporting finishes
	<-done
	fmt.Println("🚀 Analysis finished successfully!")
}
