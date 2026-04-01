// Package main is the entry point for the Wormhole CLI.
package main

import (
	"os"

	"github.com/lucientong/wormhole/cmd/wormhole/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
