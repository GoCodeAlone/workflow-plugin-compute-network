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
	var externalPeerID, externalPeerBaseURL, externalPeerContentRef, externalPeerIdentitySHA256, externalPeerExpectedSHA256 string
	var captiveTopologyRef string
	var externalPeerMultiNode bool
	var captiveExternalMultiNode bool
	flags.StringVar(&mode, "mode", "", "conformance mode: p2p, captive, tor, or tailnet")
	flags.StringVar(&artifact, "artifact", "", "artifact JSON output path")
	flags.StringVar(&workDir, "work-dir", "", "temporary work directory")
	flags.StringVar(&bindHost, "bind", "127.0.0.1", "bind host for local conformance servers")
	flags.StringVar(&externalPeerID, "external-peer-id", "", "external P2P source peer id")
	flags.StringVar(&externalPeerBaseURL, "external-peer-base-url", "", "external P2P source peer base URL")
	flags.StringVar(&externalPeerContentRef, "external-peer-content-ref", "", "external P2P source content ref")
	flags.StringVar(&externalPeerIdentitySHA256, "external-peer-identity-sha256", "", "external P2P source identity digest")
	flags.StringVar(&externalPeerExpectedSHA256, "external-peer-expected-sha256", "", "optional expected sha256 digest for external P2P content")
	flags.BoolVar(&externalPeerMultiNode, "external-peer-multi-node", false, "mark external P2P peer as separately verified distinct-node topology")
	flags.StringVar(&captiveTopologyRef, "captive-topology-ref", "", "caller-supplied evidence ref for externally verified captive topology")
	flags.BoolVar(&captiveExternalMultiNode, "captive-external-multi-node", false, "mark captive topology as separately verified distinct-node topology")
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
	var externalPeer *transport.ExternalContentPeer
	if externalPeerID != "" || externalPeerBaseURL != "" || externalPeerContentRef != "" || externalPeerIdentitySHA256 != "" || externalPeerExpectedSHA256 != "" || externalPeerMultiNode {
		if mode != string(transport.ModeP2P) {
			return fmt.Errorf("external peer flags are only valid with --mode p2p")
		}
		externalPeer = &transport.ExternalContentPeer{
			PeerID:            externalPeerID,
			BaseURL:           externalPeerBaseURL,
			ContentRef:        externalPeerContentRef,
			IdentitySHA256:    externalPeerIdentitySHA256,
			ExpectedSHA256:    externalPeerExpectedSHA256,
			ExternalMultiNode: externalPeerMultiNode,
		}
	}
	var captiveTopology *transport.CaptiveTopologyEvidence
	if captiveTopologyRef != "" || captiveExternalMultiNode {
		if mode != string(transport.ModeCaptive) {
			return fmt.Errorf("captive topology flags are only valid with --mode captive")
		}
		captiveTopology = &transport.CaptiveTopologyEvidence{
			TopologyRef:       captiveTopologyRef,
			ExternalMultiNode: captiveExternalMultiNode,
		}
	}
	result, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:                transport.Mode(mode),
		ArtifactPath:        artifact,
		WorkDir:             workDir,
		BindHost:            bindHost,
		ExternalContentPeer: externalPeer,
		CaptiveTopology:     captiveTopology,
		ProviderVersion:     internal.Version,
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
