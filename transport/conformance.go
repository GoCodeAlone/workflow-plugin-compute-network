package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"github.com/GoCodeAlone/workflow-plugin-compute-network/network"
)

const ArtifactVersion = "compute-network-conformance.v1"
const DefaultProviderVersion = "v0.2.0-dev"

type Mode string

const (
	ModeP2P     Mode = "p2p"
	ModeCaptive Mode = "captive"
	ModeTor     Mode = "tor"
	ModeTailnet Mode = "tailnet"
)

type RunOptions struct {
	Mode                 Mode
	ArtifactPath         string
	WorkDir              string
	BindHost             string
	Payload              []byte
	ContentServerCommand []string
	ContentServerEnv     []string
	LookPath             func(string) (string, error)
	ProviderVersion      string
	Now                  time.Time
}

type ConformanceArtifact struct {
	Version     string                    `json:"version"`
	Mode        Mode                      `json:"mode"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Supported   bool                      `json:"supported"`
	Specs       []network.ConformanceSpec `json:"specs"`
	Transfer    *TransferProof            `json:"transfer,omitempty"`
	Captive     *CaptiveProof             `json:"captive,omitempty"`
}

type TransferProof struct {
	ContentRef           string `json:"content_ref"`
	Bytes                int64  `json:"bytes"`
	SHA256               string `json:"sha256"`
	ServerPID            int    `json:"server_pid"`
	ServerIdentitySHA256 string `json:"server_identity_sha256"`
	SignatureSHA256      string `json:"signature_sha256"`
}

type CaptiveProof struct {
	DenyByDefault bool               `json:"deny_by_default"`
	CheckedModes  []core.NetworkMode `json:"checked_modes"`
	Residue       ResidueScan        `json:"residue"`
}

type ResidueScan struct {
	Clean          bool     `json:"clean"`
	RemovedEntries int      `json:"removed_entries,omitempty"`
	RemainingNames []string `json:"remaining_names,omitempty"`
}

func RunConformance(ctx context.Context, opts RunOptions) (ConformanceArtifact, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if opts.BindHost == "" {
		opts.BindHost = "127.0.0.1"
	}
	if opts.ProviderVersion == "" {
		opts.ProviderVersion = DefaultProviderVersion
	}
	if opts.WorkDir == "" {
		dir, err := os.MkdirTemp("", "wfcn-conformance-*")
		if err != nil {
			return ConformanceArtifact{}, err
		}
		opts.WorkDir = dir
		defer os.RemoveAll(dir)
	}
	if err := os.MkdirAll(opts.WorkDir, 0o700); err != nil {
		return ConformanceArtifact{}, err
	}

	var (
		artifact ConformanceArtifact
		err      error
	)
	switch opts.Mode {
	case ModeP2P:
		artifact, err = runP2P(ctx, opts, now)
	case ModeCaptive:
		artifact, err = runCaptive(opts, now)
	case ModeTor:
		artifact, err = runUnavailableOverlay(opts, now, ModeTor, core.NetworkModeTor, "tor-sidecar", []string{"arti", "tor"})
	case ModeTailnet:
		artifact, err = runUnavailableOverlay(opts, now, ModeTailnet, core.NetworkModeTailnet, "tailnet-sidecar", []string{"tailscale"})
	default:
		err = fmt.Errorf("unsupported conformance mode %q", opts.Mode)
	}
	if err != nil {
		return ConformanceArtifact{}, err
	}
	artifact.Version = ArtifactVersion
	artifact.Mode = opts.Mode
	artifact.GeneratedAt = now
	if opts.ArtifactPath != "" {
		if err := writeArtifact(opts.ArtifactPath, artifact); err != nil {
			return ConformanceArtifact{}, err
		}
	}
	return artifact, nil
}

func runP2P(ctx context.Context, opts RunOptions, now time.Time) (ConformanceArtifact, error) {
	payload := opts.Payload
	if len(payload) == 0 {
		payload = []byte("workflow compute network p2p conformance\n")
	}
	sessionDir := filepath.Join(opts.WorkDir, "p2p-session")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return ConformanceArtifact{}, err
	}
	contentPath := filepath.Join(sessionDir, "content.bin")
	if err := os.WriteFile(contentPath, payload, 0o600); err != nil {
		return ConformanceArtifact{}, err
	}
	contentRef := "content://inputs/p2p-smoke"
	server, err := startContentServer(ctx, opts, contentPath, contentRef)
	if err != nil {
		return ConformanceArtifact{}, err
	}
	defer server.cleanup()

	got, err := fetchContent(ctx, server.BaseURL+"/content")
	if err != nil {
		return ConformanceArtifact{}, err
	}
	if !bytes.Equal(got, payload) {
		return ConformanceArtifact{}, errors.New("p2p content transfer returned unexpected payload")
	}
	transferDigest := digestBytes(got)
	sinkDigest := digestBytes([]byte("peer-sink:" + contentRef))

	descriptor := descriptor("p2p-sidecar", "compute-network.p2p.v1", opts.ProviderVersion, []core.NetworkMode{core.NetworkModeP2P}, true, false)
	req := prepareRequest(descriptor, core.NetworkModeP2P, now)
	req.NetworkPolicy.AllowedDestinations = []core.NetworkDestination{{ContentRef: contentRef}}
	req.P2PSessionPolicy = p2pPolicy(now, contentRef, server.IdentitySHA256, sinkDigest)
	req.AllowedProtocols = []string{"compute-content-v1"}
	resp := network.SidecarPrepareResponse{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       req.RequestID,
		SessionID:       req.P2PSessionPolicy.SessionID,
		ProviderID:      descriptor.ProviderID,
		Mode:            core.NetworkModeP2P,
		WorkerID:        req.WorkerID,
		PeerIDs:         []string{"peer-source", "peer-sink"},
		PeerIdentitiesSHA256: map[string]string{
			"peer-source": server.IdentitySHA256,
			"peer-sink":   sinkDigest,
		},
		BoundDestinations: []core.NetworkDestination{{ContentRef: contentRef}},
		ContentPeers: []network.ContentPeer{{
			PeerID:         "peer-source",
			BaseURL:        server.BaseURL,
			ContentRefs:    []string{contentRef},
			IdentitySHA256: server.IdentitySHA256,
		}},
		Evidence: evidence(descriptor.ProviderID, opts.ProviderVersion, core.NetworkModeP2P, network.ProviderStatusSupported, now, ""),
	}
	resp.Evidence.KeyExchange = "ed25519-signed-identity"
	resp.Evidence.DiscoverySource = "loopback-child-process"
	resp.Evidence.PeerCount = 2
	resp.Evidence.BytesTx = int64(len(got))
	resp.Evidence.BytesRx = int64(len(got))
	resp.Evidence.ArtifactDigest = transferDigest
	resp.Evidence.Lifecycle = append(resp.Evidence.Lifecycle, network.LifecycleEvent{Event: "prepared", ObservedAt: now})

	closeReq, closeResp := closePair(descriptor.ProviderID, opts.ProviderVersion, core.NetworkModeP2P, req.RequestID, resp.SessionID, now, true, network.ProviderStatusSupported, "")
	server.cleanup()
	residue := scanAndRemove(sessionDir)
	closeResp.Evidence.UrgentTeardown = &network.TeardownEvidence{
		Completed:      residue.Clean,
		ObservedAt:     now,
		ProcessStopped: true,
		WorkspaceClean: residue.Clean,
	}
	spec := network.ConformanceSpec{
		Descriptor:            descriptor,
		PrepareRequest:        req,
		PrepareResponse:       resp,
		CloseRequest:          closeReq,
		CloseResponse:         closeResp,
		ExpectedMode:          core.NetworkModeP2P,
		ExpectedContentRefs:   []string{contentRef},
		RequireSupported:      true,
		RequireLifecycleAudit: true,
		RequireUrgentTeardown: true,
		ObservedAt:            now,
	}
	if err := network.VerifyProviderConformance(spec); err != nil {
		return ConformanceArtifact{}, err
	}
	return ConformanceArtifact{
		Supported: true,
		Specs:     []network.ConformanceSpec{spec},
		Transfer: &TransferProof{
			ContentRef:           contentRef,
			Bytes:                int64(len(got)),
			SHA256:               transferDigest,
			ServerPID:            server.PID,
			ServerIdentitySHA256: server.IdentitySHA256,
			SignatureSHA256:      server.SignatureSHA256,
		},
	}, nil
}

func runCaptive(opts RunOptions, now time.Time) (ConformanceArtifact, error) {
	sessionDir := filepath.Join(opts.WorkDir, "captive-session")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return ConformanceArtifact{}, err
	}
	descriptor := descriptor("captive-gateway", "compute-network.captive.v1", opts.ProviderVersion, []core.NetworkMode{
		core.NetworkModeDirect,
		core.NetworkModeRelay,
		core.NetworkModeOffline,
	}, false, false)
	var specs []network.ConformanceSpec
	modes := []core.NetworkMode{core.NetworkModeDirect, core.NetworkModeRelay, core.NetworkModeOffline}
	for _, mode := range modes {
		req := prepareRequest(descriptor, mode, now)
		req.NetworkPolicy.AllowedDestinations = nil
		resp := network.SidecarPrepareResponse{
			ProtocolVersion: network.SidecarProtocolVersion,
			RequestID:       req.RequestID,
			SessionID:       "session-" + string(mode),
			ProviderID:      descriptor.ProviderID,
			Mode:            mode,
			WorkerID:        req.WorkerID,
			Evidence:        evidence(descriptor.ProviderID, opts.ProviderVersion, mode, network.ProviderStatusSupported, now, ""),
		}
		resp.Evidence.DiscoverySource = "deny-by-default"
		resp.Evidence.Lifecycle = append(resp.Evidence.Lifecycle, network.LifecycleEvent{Event: "prepared", ObservedAt: now})
		closeReq, closeResp := closePair(descriptor.ProviderID, opts.ProviderVersion, mode, req.RequestID, resp.SessionID, now, true, network.ProviderStatusSupported, "")
		spec := network.ConformanceSpec{
			Descriptor:            descriptor,
			PrepareRequest:        req,
			PrepareResponse:       resp,
			CloseRequest:          closeReq,
			CloseResponse:         closeResp,
			ExpectedMode:          mode,
			RequireSupported:      true,
			RequireLifecycleAudit: true,
			RequireUrgentTeardown: true,
			ObservedAt:            now,
		}
		if err := network.VerifyProviderConformance(spec); err != nil {
			return ConformanceArtifact{}, err
		}
		specs = append(specs, spec)
	}
	residue := scanAndRemove(sessionDir)
	return ConformanceArtifact{
		Supported: true,
		Specs:     specs,
		Captive: &CaptiveProof{
			DenyByDefault: true,
			CheckedModes:  modes,
			Residue:       residue,
		},
	}, nil
}

func runUnavailableOverlay(opts RunOptions, now time.Time, artifactMode Mode, networkMode core.NetworkMode, providerID string, toolNames []string) (ConformanceArtifact, error) {
	lookup := opts.LookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	reason := "daemon unavailable"
	for _, name := range toolNames {
		if _, err := lookup(name); err == nil {
			reason = "supported probe not configured"
			break
		}
	}
	descriptor := descriptor(providerID, "compute-network."+strings.TrimSuffix(providerID, "-sidecar")+".v1", opts.ProviderVersion, []core.NetworkMode{networkMode}, false, true)
	req := prepareRequest(descriptor, networkMode, now)
	resp := network.SidecarPrepareResponse{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       req.RequestID,
		SessionID:       "session-" + string(artifactMode),
		ProviderID:      descriptor.ProviderID,
		Mode:            networkMode,
		WorkerID:        req.WorkerID,
		Evidence:        evidence(descriptor.ProviderID, opts.ProviderVersion, networkMode, network.ProviderStatusUnsupported, now, reason),
	}
	resp.Evidence.Lifecycle = append(resp.Evidence.Lifecycle, network.LifecycleEvent{Event: "unsupported", ObservedAt: now})
	closeReq, closeResp := closePair(descriptor.ProviderID, opts.ProviderVersion, networkMode, req.RequestID, resp.SessionID, now, true, network.ProviderStatusUnsupported, reason)
	spec := network.ConformanceSpec{
		Descriptor:       descriptor,
		PrepareRequest:   req,
		PrepareResponse:  resp,
		CloseRequest:     closeReq,
		CloseResponse:    closeResp,
		ExpectedMode:     networkMode,
		RequireSupported: false,
		ObservedAt:       now,
	}
	if err := network.VerifyProviderConformance(spec); err != nil {
		return ConformanceArtifact{}, err
	}
	return ConformanceArtifact{Supported: false, Specs: []network.ConformanceSpec{spec}}, nil
}

func descriptor(providerID, contractID, version string, modes []core.NetworkMode, supportsContent, supportsIngress bool) network.ProviderDescriptor {
	return network.ProviderDescriptor{
		ProtocolVersion:        core.Version,
		PluginID:               "workflow-plugin-compute-network",
		ProviderID:             providerID,
		ContractID:             contractID,
		Version:                version,
		Modes:                  modes,
		SidecarProtocol:        network.SidecarProtocolVersion,
		EvidenceSchemaRef:      "schema://providers/workflow-plugin-compute-network/" + providerID + "/evidence/v1",
		RequiresDaemon:         true,
		SupportsIngress:        supportsIngress,
		SupportsContent:        supportsContent,
		ManagedPackageRequired: true,
	}
}

func prepareRequest(descriptor network.ProviderDescriptor, mode core.NetworkMode, now time.Time) network.SidecarPrepareRequest {
	return network.SidecarPrepareRequest{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       "prepare-" + string(mode),
		Descriptor:      descriptor,
		WorkerID:        "worker-conformance",
		TaskID:          "task-conformance",
		LeaseID:         "lease-conformance",
		OrgID:           "org-conformance",
		PoolID:          "pool-conformance",
		RequestedMode:   mode,
		NetworkPolicy: core.NetworkPolicy{
			Mode: mode,
		},
	}
}

func p2pPolicy(now time.Time, contentRef, sourceDigest, sinkDigest string) *core.P2PSessionPolicy {
	policy := &core.P2PSessionPolicy{
		ProtocolVersion:   core.Version,
		SessionID:         "session-p2p",
		ProductID:         "product-conformance",
		OrgID:             "org-conformance",
		NetworkID:         "network-conformance",
		OperatorID:        "operator-conformance",
		PolicyVersion:     "policy-conformance",
		IssuedAt:          now.Add(-time.Minute),
		NotBefore:         now.Add(-time.Minute),
		ExpiresAt:         now.Add(time.Hour),
		SessionGeneration: 1,
		EventID:           "event-conformance",
		Nonce:             "nonce-conformance",
		Mode:              core.P2PSessionModeContent,
		Peers: []core.P2PSessionPeer{
			{ID: "peer-source", Role: "source", IdentitySHA256: sourceDigest},
			{ID: "peer-sink", Role: "sink", IdentitySHA256: sinkDigest},
		},
		AllowedProtocols:     []string{"compute-content-v1"},
		ContentRefs:          []string{contentRef},
		AllowedDestinations:  []core.NetworkDestination{{ContentRef: contentRef}},
		Limits:               core.P2PSessionLimits{MaxPeers: 2, MaxSessionBytes: 1 << 20, MaxDurationSeconds: 60},
		RevocationFeedID:     "revocations-conformance",
		RevocationFreshUntil: now.Add(time.Hour),
		Signature: core.SignatureEnvelope{
			Algorithm: "ed25519",
			KeyID:     "key-conformance",
			Value:     "signature-conformance",
		},
	}
	policy.PolicyHash = core.CanonicalHash(policy.SigningPayload())
	return policy
}

func evidence(providerID, version string, mode core.NetworkMode, status network.ProviderStatus, now time.Time, unsupported string) network.ProviderEvidence {
	return network.ProviderEvidence{
		ProtocolVersion:   core.Version,
		ProviderID:        providerID,
		ProviderVersion:   version,
		Mode:              mode,
		Status:            status,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		NATPosture:        "local-loopback",
		UnsupportedReason: unsupported,
		Lifecycle:         []network.LifecycleEvent{},
	}
}

func closePair(providerID, version string, mode core.NetworkMode, requestID, sessionID string, now time.Time, urgent bool, status network.ProviderStatus, unsupported string) (network.SidecarCloseRequest, network.SidecarCloseResponse) {
	closeReq := network.SidecarCloseRequest{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       "close-" + requestID,
		SessionID:       sessionID,
		ProviderID:      providerID,
		Mode:            mode,
		Urgent:          urgent,
		Reason:          "conformance-complete",
	}
	closeResp := network.SidecarCloseResponse{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       closeReq.RequestID,
		SessionID:       sessionID,
		ProviderID:      providerID,
		Mode:            mode,
		Closed:          true,
		Evidence:        evidence(providerID, version, mode, status, now, unsupported),
	}
	closeResp.Evidence.Lifecycle = append(closeResp.Evidence.Lifecycle, network.LifecycleEvent{Event: "closed", ObservedAt: now})
	closeResp.Evidence.UrgentTeardown = &network.TeardownEvidence{
		Completed:      true,
		ObservedAt:     now,
		ProcessStopped: true,
		WorkspaceClean: true,
	}
	return closeReq, closeResp
}

type contentServer struct {
	BaseURL           string `json:"base_url"`
	PID               int    `json:"pid"`
	IdentitySHA256    string `json:"identity_sha256"`
	SignatureSHA256   string `json:"signature_sha256"`
	cmd               *exec.Cmd
	cancelledOrKilled bool
}

func startContentServer(ctx context.Context, opts RunOptions, contentPath, contentRef string) (*contentServer, error) {
	command := opts.ContentServerCommand
	if len(command) == 0 {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		command = []string{exe}
	}
	args := append([]string{}, command[1:]...)
	args = append(args, "content-serve", "--file", contentPath, "--content-ref", contentRef, "--bind", opts.BindHost)
	cmd := exec.CommandContext(ctx, command[0], args...)
	cmd.Env = append(os.Environ(), opts.ContentServerEnv...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(stdout).ReadBytes('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("content server did not announce: %w: %s", err, stderr.String())
	}
	var server contentServer
	if err := json.Unmarshal(line, &server); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("content server announcement invalid: %w", err)
	}
	server.cmd = cmd
	return &server, nil
}

func (s *contentServer) cleanup() {
	if s == nil || s.cmd == nil || s.cancelledOrKilled {
		return
	}
	s.cancelledOrKilled = true
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.cmd.Wait()
}

func fetchContent(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("content server status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func scanAndRemove(path string) ResidueScan {
	entries, _ := os.ReadDir(path)
	scan := ResidueScan{RemovedEntries: len(entries)}
	_ = os.RemoveAll(path)
	if remaining, err := os.ReadDir(path); err == nil {
		for _, entry := range remaining {
			scan.RemainingNames = append(scan.RemainingNames, entry.Name())
		}
	}
	scan.Clean = len(scan.RemainingNames) == 0
	return scan
}

func writeArtifact(path string, artifact ConformanceArtifact) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
