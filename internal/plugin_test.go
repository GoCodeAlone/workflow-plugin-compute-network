package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"github.com/GoCodeAlone/workflow-plugin-compute-network/network"
)

func TestManifest(t *testing.T) {
	manifest := NewPlugin().Manifest()
	if manifest.Name != "workflow-plugin-compute-network" {
		t.Fatalf("name = %q", manifest.Name)
	}
	if manifest.Version != Version {
		t.Fatalf("version = %q, want %q", manifest.Version, Version)
	}
	if strings.Contains(strings.ToLower(manifest.Description), "template") ||
		strings.Contains(strings.ToLower(manifest.Description), "scaffold") {
		t.Fatalf("manifest carries placeholder text: %q", manifest.Description)
	}
}

func TestPluginJSONReferencesNetworkProviders(t *testing.T) {
	root := filepath.Clean("..")
	data, err := os.ReadFile(filepath.Join(root, "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Name                string `json:"name"`
		Private             bool   `json:"private"`
		NetworkProvidersRef string `json:"networkProvidersRef"`
		Dependencies        []struct {
			Name       string `json:"name"`
			Constraint string `json:"constraint"`
		} `json:"dependencies"`
		Capabilities struct {
			ConfigProvider bool     `json:"configProvider"`
			ModuleTypes    []string `json:"moduleTypes"`
			StepTypes      []string `json:"stepTypes"`
			TriggerTypes   []string `json:"triggerTypes"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "workflow-plugin-compute-network" || manifest.Private {
		t.Fatalf("unexpected plugin identity: %+v", manifest)
	}
	if manifest.NetworkProvidersRef != "network-providers.json" {
		t.Fatalf("networkProvidersRef = %q", manifest.NetworkProvidersRef)
	}
	var coreDependencyFound bool
	for _, dependency := range manifest.Dependencies {
		if dependency.Name == "workflow-plugin-compute-core" {
			coreDependencyFound = true
			if dependency.Constraint != ">=0.7.0" {
				t.Fatalf("compute-core dependency constraint = %q", dependency.Constraint)
			}
		}
	}
	if !coreDependencyFound {
		t.Fatal("compute-core dependency not found")
	}
	if manifest.Capabilities.ConfigProvider ||
		len(manifest.Capabilities.ModuleTypes) != 0 ||
		len(manifest.Capabilities.StepTypes) != 0 ||
		len(manifest.Capabilities.TriggerTypes) != 0 {
		t.Fatalf("network contracts plugin should not advertise workflow execution surfaces: %+v", manifest.Capabilities)
	}

	catalogData, err := os.ReadFile(filepath.Join(root, manifest.NetworkProvidersRef))
	if err != nil {
		t.Fatal(err)
	}
	var catalog network.ProviderCatalog
	if err := json.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("network provider catalog invalid: %v", err)
	}
	got := map[string]network.ProviderDescriptor{}
	for _, provider := range catalog.Providers {
		got[provider.ProviderID] = provider
	}
	for providerID, mode := range map[string]core.NetworkMode{
		"captive-gateway": core.NetworkModeRelay,
		"p2p-sidecar":     core.NetworkModeP2P,
		"tor-sidecar":     core.NetworkModeTor,
		"tailnet-sidecar": core.NetworkModeTailnet,
	} {
		provider, ok := got[providerID]
		if !ok {
			t.Fatalf("provider %q missing from catalog", providerID)
		}
		if !slices.Contains(provider.Modes, mode) {
			t.Fatalf("provider %q modes = %+v, missing %q", providerID, provider.Modes, mode)
		}
		if provider.PluginID != "workflow-plugin-compute-network" || !provider.ManagedPackageRequired {
			t.Fatalf("provider %q has invalid boundary metadata: %+v", providerID, provider)
		}
	}
}

func TestPluginContractsAdvertiseNetworkProviderContracts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "plugin.contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contracts struct {
		Contracts []struct {
			Name       string   `json:"name"`
			GoType     string   `json:"goType"`
			Guarantees []string `json:"guarantees"`
		} `json:"contracts"`
		ProtocolTypes []struct {
			Name            string `json:"name"`
			GoType          string `json:"goType"`
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"protocolTypes"`
	}
	if err := json.Unmarshal(data, &contracts); err != nil {
		t.Fatal(err)
	}
	var sidecarFound, conformanceFound, artifactFound, policyFound bool
	for _, contract := range contracts.Contracts {
		switch contract.Name {
		case "NetworkProviderSidecar":
			sidecarFound = contract.GoType == "github.com/GoCodeAlone/workflow-plugin-compute-network/network.SidecarPrepareRequest" &&
				slices.Contains(contract.Guarantees, "no-policy-expansion")
		case "NetworkProviderConformance":
			conformanceFound = contract.GoType == "github.com/GoCodeAlone/workflow-plugin-compute-network/network.ConformanceSpec" &&
				slices.Contains(contract.Guarantees, "unsupported-does-not-advertise-support")
		case "NetworkProviderConformanceArtifact":
			artifactFound = contract.GoType == "github.com/GoCodeAlone/workflow-plugin-compute-network/transport.ConformanceArtifact" &&
				slices.Contains(contract.Guarantees, "p2p-real-content-transfer") &&
				slices.Contains(contract.Guarantees, "p2p-external-peer-transfer") &&
				slices.Contains(contract.Guarantees, "captive-external-topology-evidence") &&
				slices.Contains(contract.Guarantees, "captive-deny-by-default")
		}
	}
	for _, typ := range contracts.ProtocolTypes {
		if typ.Name == "NetworkPolicy" &&
			typ.GoType == "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol.NetworkPolicy" &&
			typ.ProtocolVersion == core.Version {
			policyFound = true
		}
	}
	if !sidecarFound || !conformanceFound || !artifactFound || !policyFound {
		t.Fatalf("network contracts incomplete: sidecar=%t conformance=%t artifact=%t policy=%t", sidecarFound, conformanceFound, artifactFound, policyFound)
	}
}
