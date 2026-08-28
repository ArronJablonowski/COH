// Command architecturecatalog generates deterministic architecture evidence.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/architecturecatalog"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	flags := flag.NewFlagSet("architecturecatalog", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	goBinary := flags.String("go", "go", "Go executable")
	output := flags.String("output", "docs/architecture/catalogs", "catalog directory")
	declarations := flags.String("declarations", "contracts/architecture-catalog/v1/source-declarations.json", "source declarations")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 64
	}
	absoluteOutput := *output
	if !filepath.IsAbs(absoluteOutput) {
		absoluteOutput = filepath.Join(*root, absoluteOutput)
	}
	if err := os.MkdirAll(absoluteOutput, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "architecturecatalog: output unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := architecturecatalog.Generate(ctx, *root, *goBinary, *declarations, absoluteOutput); err != nil {
		fmt.Fprintf(os.Stderr, "architecturecatalog: %v\n", err)
		return 2
	}
	if err := architecturecatalog.ValidateDirectory(absoluteOutput); err != nil {
		fmt.Fprintf(os.Stderr, "architecturecatalog: %v\n", err)
		return 2
	}
	return 0
}
