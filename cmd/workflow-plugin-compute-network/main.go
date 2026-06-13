package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/GoCodeAlone/workflow-plugin-compute-network/internal"
	"github.com/GoCodeAlone/workflow-plugin-compute-network/transport"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var version = "0.0.0"

func main() {
	internal.Version = version
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "conformance":
			if err := runConformance(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			return
		case "content-serve":
			if err := transport.ServeContentProcess(context.Background(), os.Args, os.Stdout, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			return
		}
	}
	sdk.Serve(internal.NewPlugin(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)),
	)
}

func runConformance(args []string) error {
	flags := flag.NewFlagSet("conformance", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var mode, artifact, workDir, bindHost string
	flags.StringVar(&mode, "mode", "", "conformance mode: p2p, captive, tor, or tailnet")
	flags.StringVar(&artifact, "artifact", "", "artifact JSON output path")
	flags.StringVar(&workDir, "work-dir", "", "temporary work directory")
	flags.StringVar(&bindHost, "bind", "127.0.0.1", "bind host for local conformance servers")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if mode == "" {
		return fmt.Errorf("--mode is required")
	}
	if artifact == "" {
		return fmt.Errorf("--artifact is required")
	}
	result, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:            transport.Mode(mode),
		ArtifactPath:    artifact,
		WorkDir:         workDir,
		BindHost:        bindHost,
		ProviderVersion: internal.Version,
	})
	if err != nil {
		return err
	}
	encoded, err := os.ReadFile(artifact)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return err
	}
	if len(result.Specs) == 0 {
		return fmt.Errorf("no conformance specs emitted")
	}
	return nil
}
