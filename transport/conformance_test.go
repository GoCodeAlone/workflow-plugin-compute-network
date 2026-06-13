package transport_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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
