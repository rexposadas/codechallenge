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

	// We limit the input size to 250 characters. Return than error if it exceeds the size limit.
	if len(input) > 250 {
		fmt.Printf("Message should less than 251 characters.")
		os.Exit(1)
	}

	// Use the inputed message to generate the keys.
	r, err := lib.ProcessMessage(input)
	if err != nil {
		fmt.Printf("failed to generate keys: %s", err)
		os.Exit(1)
	}

	// Display the result using the required format.
	fmt.Printf("%s", r.FormatOutput())
}
