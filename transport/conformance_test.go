package transport_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"github.com/GoCodeAlone/workflow-plugin-compute-network/network"
	"github.com/GoCodeAlone/workflow-plugin-compute-network/transport"
)

func TestP2PConformanceUsesSeparateContentServerProcess(t *testing.T) {
	t.Parallel()
	if os.Getenv("WFCN_HELPER_CONTENT_SERVER") == "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	artifactPath := filepath.Join(t.TempDir(), "p2p.json")

	artifact, err := transport.RunConformance(ctx, transport.RunOptions{
		Mode:                 transport.ModeP2P,
		ArtifactPath:         artifactPath,
		WorkDir:              t.TempDir(),
		ContentServerCommand: helperContentServerCommand(),
		ContentServerEnv:     []string{"WFCN_HELPER_CONTENT_SERVER=1"},
		Now:                  fixedTime(),
	})
	if err != nil {
		t.Fatalf("p2p conformance failed: %v", err)
	}
	if artifact.Mode != transport.ModeP2P || !artifact.Supported {
		t.Fatalf("unexpected artifact support state: %+v", artifact)
	}
	if artifact.Transfer == nil {
		t.Fatal("expected transfer proof")
	}
	if artifact.Transfer.ServerPID == os.Getpid() {
		t.Fatalf("content server ran in test process pid %d", artifact.Transfer.ServerPID)
	}
	if artifact.Transfer.Bytes != artifact.Specs[0].PrepareResponse.Evidence.BytesRx ||
		artifact.Transfer.Bytes != artifact.Specs[0].PrepareResponse.Evidence.BytesTx {
		t.Fatalf("transfer bytes not reflected in evidence: transfer=%d evidence=%+v", artifact.Transfer.Bytes, artifact.Specs[0].PrepareResponse.Evidence)
	}
	if artifact.Transfer.SHA256 == "" || !strings.HasPrefix(artifact.Transfer.SHA256, "sha256:") {
		t.Fatalf("missing transfer digest: %+v", artifact.Transfer)
	}
	if err := network.VerifyProviderConformance(artifact.Specs[0]); err != nil {
		t.Fatalf("p2p artifact does not satisfy conformance: %v", err)
	}
	assertArtifactRoundTrips(t, artifactPath, artifact)
}

func TestP2PConformanceCanUseExternalContentPeer(t *testing.T) {
	t.Parallel()
	payload := []byte("workflow compute external p2p peer content\n")
	peerIdentity := "sha256:" + strings.Repeat("e", 64)
	server := localExternalPeerServer(t, payload)
	artifactPath := filepath.Join(t.TempDir(), "p2p-external.json")

	artifact, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:         transport.ModeP2P,
		ArtifactPath: artifactPath,
		WorkDir:      t.TempDir(),
		ExternalContentPeer: &transport.ExternalContentPeer{
			PeerID:         "peer-source-external",
			BaseURL:        server,
			ContentRef:     "content://inputs/external-p2p-smoke",
			IdentitySHA256: peerIdentity,
			ExpectedSHA256: digestBytes(payload),
		},
		Now: fixedTime(),
	})
	if err != nil {
		t.Fatalf("external p2p conformance failed: %v", err)
	}
	if !artifact.Supported || artifact.Transfer == nil || !artifact.Transfer.ExternalPeer {
		t.Fatalf("external p2p conformance did not preserve external transfer proof: %+v", artifact.Transfer)
	}
	if artifact.Transfer.ExternalMultiNode {
		t.Fatalf("external p2p conformance must not infer multi-node topology from URL alone: %+v", artifact.Transfer)
	}
	if artifact.Transfer.ServerPID != 0 {
		t.Fatalf("external p2p conformance must not launch local content server, got pid %d", artifact.Transfer.ServerPID)
	}
	if artifact.Transfer.SourcePeerID != "peer-source-external" ||
		artifact.Transfer.ServerIdentitySHA256 != peerIdentity ||
		artifact.Transfer.SHA256 != digestBytes(payload) {
		t.Fatalf("external transfer proof mismatch: %+v", artifact.Transfer)
	}
	spec := artifact.Specs[0]
	if spec.PrepareResponse.Evidence.DiscoverySource != "external-peer-endpoint" ||
		spec.PrepareResponse.Evidence.NATPosture != "external-peer" {
		t.Fatalf("external p2p evidence did not record external discovery/posture: %+v", spec.PrepareResponse.Evidence)
	}
	if len(spec.PrepareResponse.ContentPeers) != 1 ||
		spec.PrepareResponse.ContentPeers[0].PeerID != "peer-source-external" ||
		spec.PrepareResponse.ContentPeers[0].BaseURL != server {
		t.Fatalf("external content peer not bound into conformance response: %+v", spec.PrepareResponse.ContentPeers)
	}
	if err := network.VerifyProviderConformance(spec); err != nil {
		t.Fatalf("external p2p artifact does not satisfy conformance: %v", err)
	}
	assertArtifactRoundTrips(t, artifactPath, artifact)
}

func TestP2PConformanceRejectsMalformedExternalExpectedDigest(t *testing.T) {
	t.Parallel()
	_, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:    transport.ModeP2P,
		WorkDir: t.TempDir(),
		ExternalContentPeer: &transport.ExternalContentPeer{
			PeerID:         "peer-source-external",
			BaseURL:        "https://peer.example.invalid",
			ContentRef:     "content://inputs/external-p2p-smoke",
			IdentitySHA256: "sha256:" + strings.Repeat("e", 64),
			ExpectedSHA256: "sha256:not-a-digest",
		},
		Now: fixedTime(),
	})
	if err == nil || !strings.Contains(err.Error(), "expected_sha256 must be sha256:<64 lowercase hex chars>") {
		t.Fatalf("expected malformed digest error, got %v", err)
	}
}

func TestP2PConformanceExternalPeerFetchIsBounded(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	_, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:                transport.ModeP2P,
		WorkDir:             t.TempDir(),
		ContentFetchTimeout: 10 * time.Millisecond,
		ExternalContentPeer: &transport.ExternalContentPeer{
			PeerID:         "peer-source-external",
			BaseURL:        server.URL,
			ContentRef:     "content://inputs/external-p2p-smoke",
			IdentitySHA256: "sha256:" + strings.Repeat("e", 64),
		},
		Now: fixedTime(),
	})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected bounded external fetch timeout, got %v", err)
	}
}

func TestCaptiveConformanceDeniesDirectRelayOfflineByDefault(t *testing.T) {
	t.Parallel()
	artifactPath := filepath.Join(t.TempDir(), "captive.json")
	artifact, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:         transport.ModeCaptive,
		ArtifactPath: artifactPath,
		WorkDir:      t.TempDir(),
		Now:          fixedTime(),
	})
	if err != nil {
		t.Fatalf("captive conformance failed: %v", err)
	}
	if artifact.Captive == nil || !artifact.Captive.DenyByDefault || !artifact.Captive.Residue.Clean {
		t.Fatalf("expected deny-by-default captive residue proof: %+v", artifact.Captive)
	}
	for _, mode := range []core.NetworkMode{core.NetworkModeDirect, core.NetworkModeRelay, core.NetworkModeOffline} {
		if !slices.Contains(artifact.Captive.CheckedModes, mode) {
			t.Fatalf("missing captive mode %q in %+v", mode, artifact.Captive.CheckedModes)
		}
	}
	if len(artifact.Specs) != 3 {
		t.Fatalf("expected three captive specs, got %d", len(artifact.Specs))
	}
	for _, spec := range artifact.Specs {
		if len(spec.PrepareResponse.BoundDestinations) != 0 {
			t.Fatalf("captive mode %q advertised destinations despite deny-by-default", spec.ExpectedMode)
		}
		if err := network.VerifyProviderConformance(spec); err != nil {
			t.Fatalf("captive spec %q does not satisfy conformance: %v", spec.ExpectedMode, err)
		}
	}
	assertArtifactRoundTrips(t, artifactPath, artifact)
}

func TestCaptiveConformanceRecordsExternalTopologyEvidence(t *testing.T) {
	t.Parallel()
	artifactPath := filepath.Join(t.TempDir(), "captive-external.json")
	artifact, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:         transport.ModeCaptive,
		ArtifactPath: artifactPath,
		WorkDir:      t.TempDir(),
		CaptiveTopology: &transport.CaptiveTopologyEvidence{
			TopologyRef:       "workflow-run:27913642617/task:captive-linux-first",
			ExternalMultiNode: true,
		},
		Now: fixedTime(),
	})
	if err != nil {
		t.Fatalf("captive external topology conformance failed: %v", err)
	}
	if artifact.Captive == nil ||
		artifact.Captive.TopologyRef != "workflow-run:27913642617/task:captive-linux-first" ||
		!artifact.Captive.ExternalMultiNode {
		t.Fatalf("expected captive topology evidence to round trip: %+v", artifact.Captive)
	}
	for _, spec := range artifact.Specs {
		if spec.PrepareResponse.Evidence.DiscoverySource != "external-captive-topology" {
			t.Fatalf("captive evidence did not record external topology source: %+v", spec.PrepareResponse.Evidence)
		}
		if err := network.VerifyProviderConformance(spec); err != nil {
			t.Fatalf("captive topology spec %q does not satisfy conformance: %v", spec.ExpectedMode, err)
		}
	}
	assertArtifactRoundTrips(t, artifactPath, artifact)
}

func TestCaptiveConformanceRejectsMultiNodeWithoutTopologyRef(t *testing.T) {
	t.Parallel()
	_, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:    transport.ModeCaptive,
		WorkDir: t.TempDir(),
		CaptiveTopology: &transport.CaptiveTopologyEvidence{
			ExternalMultiNode: true,
		},
		Now: fixedTime(),
	})
	if err == nil || !strings.Contains(err.Error(), "captive topology_ref is required") {
		t.Fatalf("expected missing topology ref error, got %v", err)
	}
}

func TestCaptiveConformanceRejectsUnsafeTopologyRef(t *testing.T) {
	t.Parallel()
	_, err := transport.RunConformance(context.Background(), transport.RunOptions{
		Mode:    transport.ModeCaptive,
		WorkDir: t.TempDir(),
		CaptiveTopology: &transport.CaptiveTopologyEvidence{
			TopologyRef:       "https://staging.example.invalid/proofs?token=secret",
			ExternalMultiNode: true,
		},
		Now: fixedTime(),
	})
	if err == nil || !strings.Contains(err.Error(), "captive topology_ref must be a sanitized evidence reference") {
		t.Fatalf("expected unsafe topology ref error, got %v", err)
	}
}

func TestUnavailableTorAndTailnetEmitUnsupportedEvidenceWithoutCapabilities(t *testing.T) {
	t.Parallel()
	for _, mode := range []transport.Mode{transport.ModeTor, transport.ModeTailnet} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			artifact, err := transport.RunConformance(context.Background(), transport.RunOptions{
				Mode:         mode,
				ArtifactPath: filepath.Join(t.TempDir(), string(mode)+".json"),
				WorkDir:      t.TempDir(),
				LookPath: func(string) (string, error) {
					return "", exec.ErrNotFound
				},
				Now: fixedTime(),
			})
			if err != nil {
				t.Fatalf("%s conformance failed: %v", mode, err)
			}
			if artifact.Supported {
				t.Fatalf("%s should not advertise support without a daemon/tool: %+v", mode, artifact)
			}
			spec := artifact.Specs[0]
			if spec.PrepareResponse.Evidence.Status != network.ProviderStatusUnsupported {
				t.Fatalf("%s should emit unsupported evidence: %+v", mode, spec.PrepareResponse.Evidence)
			}
			if len(spec.PrepareResponse.PeerIDs) != 0 || len(spec.PrepareResponse.BoundDestinations) != 0 || len(spec.PrepareResponse.ContentPeers) != 0 {
				t.Fatalf("%s unsupported evidence advertised capabilities: %+v", mode, spec.PrepareResponse)
			}
			if err := network.VerifyProviderConformance(spec); err != nil {
				t.Fatalf("%s unsupported artifact should satisfy no-advertisement conformance: %v", mode, err)
			}
		})
	}
}

func TestAvailableTorAndTailnetEmitSupportedEvidence(t *testing.T) {
	t.Parallel()
	t.Run("tor", func(t *testing.T) {
		t.Parallel()
		artifact, err := transport.RunConformance(context.Background(), transport.RunOptions{
			Mode:            transport.ModeTor,
			ArtifactPath:    filepath.Join(t.TempDir(), "tor.json"),
			WorkDir:         t.TempDir(),
			TorSocksAddress: "127.0.0.1:19050",
			LookPath: func(string) (string, error) {
				return "/usr/bin/tor", nil
			},
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return &nopConn{}, nil
			},
			Now: fixedTime(),
		})
		if err != nil {
			t.Fatalf("tor conformance failed: %v", err)
		}
		assertSupportedOverlay(t, artifact, network.ProviderStatusSupported)
	})
	t.Run("tailnet", func(t *testing.T) {
		t.Parallel()
		artifact, err := transport.RunConformance(context.Background(), transport.RunOptions{
			Mode:         transport.ModeTailnet,
			ArtifactPath: filepath.Join(t.TempDir(), "tailnet.json"),
			WorkDir:      t.TempDir(),
			LookPath: func(string) (string, error) {
				return "/usr/bin/tailscale", nil
			},
			RunCommand: func(context.Context, string, ...string) ([]byte, error) {
				return []byte(`{"Self":{"Online":true}}`), nil
			},
			Now: fixedTime(),
		})
		if err != nil {
			t.Fatalf("tailnet conformance failed: %v", err)
		}
		assertSupportedOverlay(t, artifact, network.ProviderStatusSupported)
	})
}

func TestContentServerHelper(t *testing.T) {
	if os.Getenv("WFCN_HELPER_CONTENT_SERVER") != "1" {
		return
	}
	if err := transport.ServeContentProcess(context.Background(), os.Args, os.Stdout, os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		os.Exit(2)
	}
	os.Exit(0)
}

func helperContentServerCommand() []string {
	return []string{os.Args[0], "-test.run=TestContentServerHelper", "--"}
}

func fixedTime() time.Time {
	return time.Date(2026, 6, 13, 22, 0, 0, 0, time.UTC)
}

func localExternalPeerServer(t *testing.T, payload []byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/content", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write(payload)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("external peer server: %v", err))
		}
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		_ = listener.Close()
	})
	return "http://" + listener.Addr().String()
}

func digestBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func assertSupportedOverlay(t *testing.T, artifact transport.ConformanceArtifact, status network.ProviderStatus) {
	t.Helper()
	if !artifact.Supported {
		t.Fatalf("expected supported artifact: %+v", artifact)
	}
	spec := artifact.Specs[0]
	if spec.PrepareResponse.Evidence.Status != status {
		t.Fatalf("status = %q, want %q", spec.PrepareResponse.Evidence.Status, status)
	}
	if spec.PrepareResponse.Evidence.UnsupportedReason != "" {
		t.Fatalf("supported overlay carried unsupported reason: %+v", spec.PrepareResponse.Evidence)
	}
	if err := network.VerifyProviderConformance(spec); err != nil {
		t.Fatalf("supported overlay should satisfy conformance: %v", err)
	}
}

func assertArtifactRoundTrips(t *testing.T, path string, want transport.ConformanceArtifact) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("artifact not written: %v", err)
	}
	var got transport.ConformanceArtifact
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("artifact is not json: %v", err)
	}
	if got.Mode != want.Mode || len(got.Specs) != len(want.Specs) {
		t.Fatalf("artifact round-trip mismatch: got=%+v want=%+v", got, want)
	}
}

type nopConn struct{}

func (*nopConn) Read([]byte) (int, error)         { return 0, errors.New("closed") }
func (*nopConn) Write([]byte) (int, error)        { return 0, errors.New("closed") }
func (*nopConn) Close() error                     { return nil }
func (*nopConn) LocalAddr() net.Addr              { return nopAddr("local") }
func (*nopConn) RemoteAddr() net.Addr             { return nopAddr("remote") }
func (*nopConn) SetDeadline(time.Time) error      { return nil }
func (*nopConn) SetReadDeadline(time.Time) error  { return nil }
func (*nopConn) SetWriteDeadline(time.Time) error { return nil }

type nopAddr string

func (a nopAddr) Network() string { return string(a) }
func (a nopAddr) String() string  { return string(a) }
