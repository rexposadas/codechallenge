package main

import (
	"fmt"
	"os"

	"github.com/rexposadas/codechallenge/lib"
)

func main() {
	// Display a sensible error if this application was ran without an argument.
	if len(os.Args) == 1 {
		fmt.Printf("Missing an argument. Add a message to use for encryption.")
		os.Exit(1)
	}
	input := os.Args[1]

	// Use the inputed message to generate the keys. If the keys exists in the file
	// system, load them.
	r, err := lib.ProcessMessage(input)
	if err != nil {
		fmt.Printf("failed to generate keys: %s", err)
		os.Exit(1)
	}

	// Display the result.
	fmt.Printf("%s", r.FormatOutput())
}
