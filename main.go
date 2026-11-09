package main

import "stash/internal/cli"

// Keep existing root build commands working alongside cmd/stash.
func main() {
	cli.Main()
}
