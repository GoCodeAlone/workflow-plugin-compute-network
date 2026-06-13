package network

import (
	"strings"
	"testing"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestProviderCatalogValidatesPublishedDescriptors(t *testing.T) {
	catalog := ProviderCatalog{
		Version: ProviderCatalogVersion,
		Providers: []ProviderDescriptor{
			testDescriptor("p2p-sidecar", core.NetworkModeP2P),
			testDescriptor("tor-sidecar", core.NetworkModeTor),
			testDescriptor("tailnet-sidecar", core.NetworkModeTailnet),
		},
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("catalog should validate: %v", err)
	}
	catalog.Providers[1].ProviderID = "p2p-sidecar"
	catalog.Providers[1].ContractID = catalog.Providers[0].ContractID
	if err := catalog.Validate(); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("expected duplicate provider identity rejection, got %v", err)
	}
}

func TestProviderDescriptorRejectsNonCanonicalTokenWhitespace(t *testing.T) {
	descriptor := testDescriptor("p2p-sidecar", core.NetworkModeP2P)
	descriptor.ProviderID = " p2p-sidecar"
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "leading or trailing whitespace") {
		t.Fatalf("expected token whitespace rejection, got %v", err)
	}
}

func TestPrepareResponseRejectsPolicyExpansion(t *testing.T) {
	now := time.Now().UTC()
	req := testPrepareRequest(now)
	resp := testPrepareResponse(now)
	resp.BoundDestinations = append(resp.BoundDestinations, core.NetworkDestination{Protocol: "tcp", Host: "extra.example", Port: 443})
	if err := resp.ValidateAgainst(req, now); err == nil || !strings.Contains(err.Error(), "expands signed policy") {
		t.Fatalf("expected policy expansion rejection, got %v", err)
	}
}

func TestPrepareResponseRejectsPeerExpansion(t *testing.T) {
	now := time.Now().UTC()
	req := testPrepareRequest(now)
	resp := testPrepareResponse(now)
	resp.PeerIDs = append(resp.PeerIDs, "peer-extra")
	if err := resp.ValidateAgainst(req, now); err == nil || !strings.Contains(err.Error(), "expands signed peer set") {
		t.Fatalf("expected peer expansion rejection, got %v", err)
	}
}

func TestProviderEvidenceRejectsUnsafeText(t *testing.T) {
	evidence := testEvidence(time.Now().UTC(), ProviderStatusUnsupported)
	evidence.UnsupportedReason = "see https://example.invalid/path?token=secret"
	if err := evidence.Validate(); err == nil || !strings.Contains(err.Error(), "raw URLs") {
		t.Fatalf("expected unsafe evidence text rejection, got %v", err)
	}
}

func TestCloseResponseRequiresUrgentTeardownEvidence(t *testing.T) {
	now := time.Now().UTC()
	closeReq := SidecarCloseRequest{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "close-1",
		SessionID:       "session-1",
		ProviderID:      "p2p-sidecar",
		Mode:            core.NetworkModeP2P,
		Urgent:          true,
	}
	closeResp := SidecarCloseResponse{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "close-1",
		SessionID:       "session-1",
		ProviderID:      "p2p-sidecar",
		Mode:            core.NetworkModeP2P,
		Closed:          true,
		Evidence:        testEvidence(now, ProviderStatusSupported),
	}
	if err := closeResp.ValidateAgainst(closeReq); err == nil || !strings.Contains(err.Error(), "urgent teardown") {
		t.Fatalf("expected urgent teardown rejection, got %v", err)
	}
	closeResp.Evidence.UrgentTeardown = &TeardownEvidence{
		Completed:      true,
		ObservedAt:     now,
		ProcessStopped: true,
		WorkspaceClean: true,
	}
	if err := closeResp.ValidateAgainst(closeReq); err != nil {
		t.Fatalf("close response should validate: %v", err)
	}
}

func TestVerifyProviderConformance(t *testing.T) {
	now := time.Now().UTC()
	spec := ConformanceSpec{
		Descriptor:            testDescriptor("p2p-sidecar", core.NetworkModeP2P),
		PrepareRequest:        testPrepareRequest(now),
		PrepareResponse:       testPrepareResponse(now),
		CloseRequest:          testCloseRequest(),
		CloseResponse:         testCloseResponse(now),
		ExpectedMode:          core.NetworkModeP2P,
		ExpectedContentRefs:   []string{"content://inputs/a"},
		RequireSupported:      true,
		RequireLifecycleAudit: true,
		RequireUrgentTeardown: true,
		ObservedAt:            now,
	}
	if err := VerifyProviderConformance(spec); err != nil {
		t.Fatalf("conformance should validate: %v", err)
	}
	spec.PrepareResponse.ContentPeers[0].ContentRefs = []string{"content://inputs/other"}
	if err := VerifyProviderConformance(spec); err == nil || !strings.Contains(err.Error(), "expected content ref") {
		t.Fatalf("expected content ref rejection, got %v", err)
	}
}

func TestUnsupportedEvidenceDoesNotAdvertiseSupport(t *testing.T) {
	now := time.Now().UTC()
	spec := ConformanceSpec{
		Descriptor:       testDescriptor("tor-sidecar", core.NetworkModeTor),
		PrepareRequest:   testPrepareRequestForMode(now, "tor-sidecar", core.NetworkModeTor),
		PrepareResponse:  testUnsupportedPrepareResponse(now, "tor-sidecar", core.NetworkModeTor),
		CloseRequest:     testCloseRequestForMode("tor-sidecar", core.NetworkModeTor, false),
		CloseResponse:    testCloseResponseForMode(now, "tor-sidecar", core.NetworkModeTor, false),
		ExpectedMode:     core.NetworkModeTor,
		RequireSupported: false,
		ObservedAt:       now,
	}
	if err := VerifyProviderConformance(spec); err != nil {
		t.Fatalf("unsupported no-advertisement evidence should validate: %v", err)
	}
	spec.PrepareResponse.PeerIDs = []string{"peer-1"}
	if err := VerifyProviderConformance(spec); err == nil || !strings.Contains(err.Error(), "unsupported evidence must not advertise") {
		t.Fatalf("expected unsupported advertisement rejection, got %v", err)
	}
}

func testDescriptor(provider string, mode core.NetworkMode) ProviderDescriptor {
	return ProviderDescriptor{
		ProtocolVersion:        core.Version,
		PluginID:               "workflow-plugin-compute-network",
		ProviderID:             provider,
		ContractID:             "compute-network." + strings.TrimSuffix(provider, "-sidecar") + ".v1",
		Version:                "v0.1.0",
		Modes:                  []core.NetworkMode{mode},
		SidecarProtocol:        SidecarProtocolVersion,
		EvidenceSchemaRef:      "schema://providers/workflow-plugin-compute-network/" + provider + "/evidence/v1",
		RequiresDaemon:         true,
		ManagedPackageRequired: true,
	}
}

func testPrepareRequest(now time.Time) SidecarPrepareRequest {
	return testPrepareRequestForMode(now, "p2p-sidecar", core.NetworkModeP2P)
}

func testPrepareRequestForMode(now time.Time, provider string, mode core.NetworkMode) SidecarPrepareRequest {
	req := SidecarPrepareRequest{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "prepare-1",
		Descriptor:      testDescriptor(provider, mode),
		WorkerID:        "worker-1",
		TaskID:          "task-1",
		LeaseID:         "lease-1",
		OrgID:           "org-1",
		PoolID:          "pool-1",
		RequestedMode:   mode,
		NetworkPolicy: core.NetworkPolicy{
			Mode: mode,
			AllowedDestinations: []core.NetworkDestination{
				{ContentRef: "content://inputs/a"},
			},
		},
		AllowedProtocols: []string{"compute-content-v1"},
	}
	if mode == core.NetworkModeP2P {
		req.P2PSessionPolicy = &core.P2PSessionPolicy{
			ProtocolVersion:   core.Version,
			SessionID:         "session-1",
			ProductID:         "product-1",
			OrgID:             "org-1",
			NetworkID:         "network-1",
			OperatorID:        "operator-1",
			PolicyVersion:     "policy-1",
			IssuedAt:          now.Add(-time.Minute),
			NotBefore:         now.Add(-time.Minute),
			ExpiresAt:         now.Add(time.Hour),
			SessionGeneration: 1,
			EventID:           "event-1",
			Nonce:             "nonce-1",
			Mode:              core.P2PSessionModeContent,
			Peers: []core.P2PSessionPeer{
				{ID: "peer-1", Role: "source", IdentitySHA256: "sha256:" + strings.Repeat("a", 64)},
				{ID: "peer-2", Role: "sink", IdentitySHA256: "sha256:" + strings.Repeat("b", 64)},
			},
			AllowedProtocols:     []string{"compute-content-v1"},
			ContentRefs:          []string{"content://inputs/a"},
			AllowedDestinations:  []core.NetworkDestination{{ContentRef: "content://inputs/a"}},
			Limits:               core.P2PSessionLimits{MaxPeers: 2, MaxSessionBytes: 1024, MaxDurationSeconds: 60},
			RevocationFeedID:     "revocations-1",
			RevocationFreshUntil: now.Add(time.Hour),
			Signature: core.SignatureEnvelope{
				Algorithm: "ed25519",
				KeyID:     "key-1",
				Value:     "signature-1",
			},
		}
		req.P2PSessionPolicy.PolicyHash = core.CanonicalHash(req.P2PSessionPolicy.SigningPayload())
	}
	return req
}

func testPrepareResponse(now time.Time) SidecarPrepareResponse {
	return SidecarPrepareResponse{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "prepare-1",
		SessionID:       "session-1",
		ProviderID:      "p2p-sidecar",
		Mode:            core.NetworkModeP2P,
		WorkerID:        "worker-1",
		PeerIDs:         []string{"peer-1", "peer-2"},
		PeerIdentitiesSHA256: map[string]string{
			"peer-1": "sha256:" + strings.Repeat("a", 64),
			"peer-2": "sha256:" + strings.Repeat("b", 64),
		},
		BoundDestinations: []core.NetworkDestination{{ContentRef: "content://inputs/a"}},
		ContentPeers: []ContentPeer{{
			PeerID:         "peer-1",
			BaseURL:        "http://127.0.0.1:19001",
			ContentRefs:    []string{"content://inputs/a"},
			IdentitySHA256: "sha256:" + strings.Repeat("a", 64),
		}},
		Evidence: testEvidence(now, ProviderStatusSupported),
	}
}

func testUnsupportedPrepareResponse(now time.Time, provider string, mode core.NetworkMode) SidecarPrepareResponse {
	return SidecarPrepareResponse{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "prepare-1",
		SessionID:       "session-1",
		ProviderID:      provider,
		Mode:            mode,
		WorkerID:        "worker-1",
		Evidence: ProviderEvidence{
			ProtocolVersion:   core.Version,
			ProviderID:        provider,
			ProviderVersion:   "v0.1.0",
			Mode:              mode,
			Status:            ProviderStatusUnsupported,
			UnsupportedReason: "daemon unavailable",
			Lifecycle: []LifecycleEvent{{
				Event:      "unsupported",
				ObservedAt: now,
			}},
		},
	}
}

func testCloseRequest() SidecarCloseRequest {
	return testCloseRequestForMode("p2p-sidecar", core.NetworkModeP2P, true)
}

func testCloseRequestForMode(provider string, mode core.NetworkMode, urgent bool) SidecarCloseRequest {
	return SidecarCloseRequest{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "close-1",
		SessionID:       "session-1",
		ProviderID:      provider,
		Mode:            mode,
		Urgent:          urgent,
		Reason:          "test",
	}
}

func testCloseResponse(now time.Time) SidecarCloseResponse {
	return testCloseResponseForMode(now, "p2p-sidecar", core.NetworkModeP2P, true)
}

func testCloseResponseForMode(now time.Time, provider string, mode core.NetworkMode, urgent bool) SidecarCloseResponse {
	evidence := ProviderEvidence{
		ProtocolVersion: core.Version,
		ProviderID:      provider,
		ProviderVersion: "v0.1.0",
		Mode:            mode,
		Status:          ProviderStatusSupported,
		Lifecycle: []LifecycleEvent{{
			Event:      "closed",
			ObservedAt: now,
		}},
	}
	if urgent {
		evidence.UrgentTeardown = &TeardownEvidence{
			Completed:      true,
			ObservedAt:     now,
			ProcessStopped: true,
			WorkspaceClean: true,
		}
	}
	return SidecarCloseResponse{
		ProtocolVersion: SidecarProtocolVersion,
		RequestID:       "close-1",
		SessionID:       "session-1",
		ProviderID:      provider,
		Mode:            mode,
		Closed:          true,
		Evidence:        evidence,
	}
}

func testEvidence(now time.Time, status ProviderStatus) ProviderEvidence {
	evidence := ProviderEvidence{
		ProtocolVersion: core.Version,
		ProviderID:      "p2p-sidecar",
		ProviderVersion: "v0.1.0",
		Mode:            core.NetworkModeP2P,
		Status:          status,
		NATPosture:      "loopback",
		DiscoverySource: "signed-peer-set",
		KeyExchange:     "signed-sha256-identity",
		PeerCount:       2,
		BytesTx:         12,
		BytesRx:         34,
		Lifecycle: []LifecycleEvent{{
			Event:      "prepared",
			ObservedAt: now,
		}},
		ArtifactDigest: "sha256:" + strings.Repeat("c", 64),
	}
	if status != ProviderStatusSupported {
		evidence.UnsupportedReason = "daemon unavailable"
	}
	return evidence
}
