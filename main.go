package main

import (
	"fmt"
	"os"

	"github.com/rexposadas/codechallenge/lib"
)

func main() {
	input := os.Args[1]
	r, err := lib.NewKeys(input)
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	fmt.Printf("%s", r.FormatOutput())
}
