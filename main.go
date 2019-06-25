package main

import (
	"fmt"
	"os"

	"github.com/rexposadas/codechallenge/lib"
)

func main() {
	input := os.Args[1]
	result, err := lib.NewResult(input)
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	fmt.Printf("%s", result.FormatOutput())

}
