package internal

import (
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var Version = "0.0.0"

type ComputeNetworkPlugin struct{}

func NewPlugin() sdk.PluginProvider {
	return &ComputeNetworkPlugin{}
}

func (p *ComputeNetworkPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-compute-network",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Public network provider contracts and conformance helpers for Workflow Compute.",
	}
}
