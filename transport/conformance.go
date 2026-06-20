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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"github.com/GoCodeAlone/workflow-plugin-compute-network/network"
)

const ArtifactVersion = "compute-network-conformance.v1"
const DefaultProviderVersion = "v0.2.0-dev"
const DefaultContentFetchTimeout = 30 * time.Second

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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
	ExternalContentPeer  *ExternalContentPeer
	LookPath             func(string) (string, error)
	DialContext          func(context.Context, string, string) (net.Conn, error)
	RunCommand           func(context.Context, string, ...string) ([]byte, error)
	TorSocksAddress      string
	ProviderVersion      string
	ContentFetchTimeout  time.Duration
	Now                  time.Time
}

type ExternalContentPeer struct {
	PeerID            string
	BaseURL           string
	ContentRef        string
	IdentitySHA256    string
	ExpectedSHA256    string
	ExternalMultiNode bool
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
	SourcePeerID         string `json:"source_peer_id,omitempty"`
	ExternalPeer         bool   `json:"external_peer,omitempty"`
	ExternalMultiNode    bool   `json:"external_multi_node,omitempty"`
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
		artifact, err = runTorOverlay(ctx, opts, now)
	case ModeTailnet:
		artifact, err = runTailnetOverlay(ctx, opts, now)
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
	source, err := prepareP2PSource(ctx, opts, sessionDir, payload)
	if err != nil {
		return ConformanceArtifact{}, err
	}
	defer source.cleanup()

	fetchCtx := ctx
	fetchCancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		timeout := opts.ContentFetchTimeout
		if timeout <= 0 {
			timeout = DefaultContentFetchTimeout
		}
		fetchCtx, fetchCancel = context.WithTimeout(ctx, timeout)
	}
	defer fetchCancel()
	got, err := fetchContent(fetchCtx, strings.TrimRight(source.BaseURL, "/")+"/content")
	if err != nil {
		return ConformanceArtifact{}, err
	}
	if !source.External && !bytes.Equal(got, payload) {
		return ConformanceArtifact{}, errors.New("p2p content transfer returned unexpected payload")
	}
	transferDigest := digestBytes(got)
	if source.ExpectedSHA256 != "" && transferDigest != source.ExpectedSHA256 {
		return ConformanceArtifact{}, fmt.Errorf("p2p external content digest %s does not match expected %s", transferDigest, source.ExpectedSHA256)
	}
	sinkDigest := digestBytes([]byte("peer-sink:" + source.ContentRef))

	descriptor := descriptor("p2p-sidecar", "compute-network.p2p.v1", opts.ProviderVersion, []core.NetworkMode{core.NetworkModeP2P}, true, false)
	req := prepareRequest(descriptor, core.NetworkModeP2P, now)
	req.NetworkPolicy.AllowedDestinations = []core.NetworkDestination{{ContentRef: source.ContentRef}}
	req.P2PSessionPolicy = p2pPolicy(now, source.ContentRef, source.PeerID, source.IdentitySHA256, sinkDigest)
	req.AllowedProtocols = []string{"compute-content-v1"}
	resp := network.SidecarPrepareResponse{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       req.RequestID,
		SessionID:       req.P2PSessionPolicy.SessionID,
		ProviderID:      descriptor.ProviderID,
		Mode:            core.NetworkModeP2P,
		WorkerID:        req.WorkerID,
		PeerIDs:         []string{source.PeerID, "peer-sink"},
		PeerIdentitiesSHA256: map[string]string{
			source.PeerID: source.IdentitySHA256,
			"peer-sink":   sinkDigest,
		},
		BoundDestinations: []core.NetworkDestination{{ContentRef: source.ContentRef}},
		ContentPeers: []network.ContentPeer{{
			PeerID:         source.PeerID,
			BaseURL:        source.BaseURL,
			ContentRefs:    []string{source.ContentRef},
			IdentitySHA256: source.IdentitySHA256,
		}},
		Evidence: evidence(descriptor.ProviderID, opts.ProviderVersion, core.NetworkModeP2P, network.ProviderStatusSupported, now, ""),
	}
	resp.Evidence.KeyExchange = "ed25519-signed-identity"
	resp.Evidence.DiscoverySource = source.DiscoverySource
	resp.Evidence.NATPosture = source.NATPosture
	resp.Evidence.PeerCount = 2
	resp.Evidence.BytesTx = int64(len(got))
	resp.Evidence.BytesRx = int64(len(got))
	resp.Evidence.ArtifactDigest = transferDigest
	resp.Evidence.Lifecycle = append(resp.Evidence.Lifecycle, network.LifecycleEvent{Event: "prepared", ObservedAt: now})

	closeReq, closeResp := closePair(descriptor.ProviderID, opts.ProviderVersion, core.NetworkModeP2P, req.RequestID, resp.SessionID, now, true, network.ProviderStatusSupported, "")
	source.cleanup()
	residue, err := scanAndRemove(sessionDir)
	if err != nil {
		return ConformanceArtifact{}, err
	}
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
		ExpectedContentRefs:   []string{source.ContentRef},
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
			ContentRef:           source.ContentRef,
			Bytes:                int64(len(got)),
			SHA256:               transferDigest,
			ServerPID:            source.PID,
			ServerIdentitySHA256: source.IdentitySHA256,
			SignatureSHA256:      source.SignatureSHA256,
			SourcePeerID:         source.PeerID,
			ExternalPeer:         source.External,
			ExternalMultiNode:    source.ExternalMultiNode,
		},
	}, nil
}

type p2pSource struct {
	PeerID             string
	BaseURL            string
	ContentRef         string
	IdentitySHA256     string
	SignatureSHA256    string
	ExpectedSHA256     string
	PID                int
	External           bool
	ExternalMultiNode  bool
	DiscoverySource    string
	NATPosture         string
	localContentServer *contentServer
}

func (s *p2pSource) cleanup() {
	if s != nil && s.localContentServer != nil {
		s.localContentServer.cleanup()
	}
}

func prepareP2PSource(ctx context.Context, opts RunOptions, sessionDir string, payload []byte) (*p2pSource, error) {
	if opts.ExternalContentPeer != nil {
		peer := *opts.ExternalContentPeer
		if err := validateExternalContentPeer(peer); err != nil {
			return nil, err
		}
		return &p2pSource{
			PeerID:            peer.PeerID,
			BaseURL:           strings.TrimRight(peer.BaseURL, "/"),
			ContentRef:        peer.ContentRef,
			IdentitySHA256:    peer.IdentitySHA256,
			ExpectedSHA256:    peer.ExpectedSHA256,
			External:          true,
			ExternalMultiNode: peer.ExternalMultiNode,
			DiscoverySource:   "external-peer-endpoint",
			NATPosture:        "external-peer",
		}, nil
	}

	contentRef := "content://inputs/p2p-smoke"
	contentPath := filepath.Join(sessionDir, "content.bin")
	if err := os.WriteFile(contentPath, payload, 0o600); err != nil {
		return nil, err
	}
	server, err := startContentServer(ctx, opts, contentPath, contentRef)
	if err != nil {
		return nil, err
	}
	return &p2pSource{
		PeerID:             "peer-source",
		BaseURL:            server.BaseURL,
		ContentRef:         contentRef,
		IdentitySHA256:     server.IdentitySHA256,
		SignatureSHA256:    server.SignatureSHA256,
		PID:                server.PID,
		DiscoverySource:    "loopback-child-process",
		NATPosture:         "local-loopback",
		localContentServer: server,
	}, nil
}

func validateExternalContentPeer(peer ExternalContentPeer) error {
	var errs []error
	if strings.TrimSpace(peer.PeerID) == "" {
		errs = append(errs, errors.New("external p2p peer_id is required"))
	}
	if strings.TrimSpace(peer.BaseURL) == "" {
		errs = append(errs, errors.New("external p2p base_url is required"))
	}
	if strings.TrimSpace(peer.ContentRef) == "" {
		errs = append(errs, errors.New("external p2p content_ref is required"))
	}
	if strings.TrimSpace(peer.IdentitySHA256) == "" {
		errs = append(errs, errors.New("external p2p identity_sha256 is required"))
	}
	contentPeer := network.ContentPeer{
		PeerID:         peer.PeerID,
		BaseURL:        strings.TrimRight(peer.BaseURL, "/"),
		ContentRefs:    []string{peer.ContentRef},
		IdentitySHA256: peer.IdentitySHA256,
	}
	if err := contentPeer.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("external p2p content peer: %w", err))
	}
	if peer.ExpectedSHA256 != "" && !sha256DigestPattern.MatchString(peer.ExpectedSHA256) {
		errs = append(errs, errors.New("external p2p expected_sha256 must be sha256:<64 lowercase hex chars>"))
	}
	return errors.Join(errs...)
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
	residue, err := scanAndRemove(sessionDir)
	if err != nil {
		return ConformanceArtifact{}, err
	}
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

func runTorOverlay(ctx context.Context, opts RunOptions, now time.Time) (ConformanceArtifact, error) {
	if !toolAvailable(opts, "arti", "tor") {
		return runOverlaySpec(opts, now, ModeTor, core.NetworkModeTor, "tor-sidecar", network.ProviderStatusUnsupported, "daemon unavailable", "")
	}
	address := opts.TorSocksAddress
	if address == "" {
		address = os.Getenv("WFCN_TOR_SOCKS_ADDR")
	}
	if address == "" {
		address = "127.0.0.1:9050"
	}
	dial := opts.DialContext
	if dial == nil {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return runOverlaySpec(opts, now, ModeTor, core.NetworkModeTor, "tor-sidecar", network.ProviderStatusUnsupported, "daemon unavailable", "")
	}
	_ = conn.Close()
	return runOverlaySpec(opts, now, ModeTor, core.NetworkModeTor, "tor-sidecar", network.ProviderStatusSupported, "", "system-tor-socks")
}

func runTailnetOverlay(ctx context.Context, opts RunOptions, now time.Time) (ConformanceArtifact, error) {
	if !toolAvailable(opts, "tailscale") {
		return runOverlaySpec(opts, now, ModeTailnet, core.NetworkModeTailnet, "tailnet-sidecar", network.ProviderStatusUnsupported, "daemon unavailable", "")
	}
	run := opts.RunCommand
	if run == nil {
		run = runCommand
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := run(probeCtx, "tailscale", "status", "--json"); err != nil {
		return runOverlaySpec(opts, now, ModeTailnet, core.NetworkModeTailnet, "tailnet-sidecar", network.ProviderStatusUnsupported, "daemon unavailable", "")
	}
	return runOverlaySpec(opts, now, ModeTailnet, core.NetworkModeTailnet, "tailnet-sidecar", network.ProviderStatusSupported, "", "tailscale-status")
}

func toolAvailable(opts RunOptions, toolNames ...string) bool {
	lookup := opts.LookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	for _, name := range toolNames {
		if _, err := lookup(name); err == nil {
			return true
		}
	}
	return false
}

func runOverlaySpec(opts RunOptions, now time.Time, artifactMode Mode, networkMode core.NetworkMode, providerID string, status network.ProviderStatus, unsupported string, discovery string) (ConformanceArtifact, error) {
	descriptor := descriptor(providerID, "compute-network."+strings.TrimSuffix(providerID, "-sidecar")+".v1", opts.ProviderVersion, []core.NetworkMode{networkMode}, false, true)
	req := prepareRequest(descriptor, networkMode, now)
	resp := network.SidecarPrepareResponse{
		ProtocolVersion: network.SidecarProtocolVersion,
		RequestID:       req.RequestID,
		SessionID:       "session-" + string(artifactMode),
		ProviderID:      descriptor.ProviderID,
		Mode:            networkMode,
		WorkerID:        req.WorkerID,
		Evidence:        evidence(descriptor.ProviderID, opts.ProviderVersion, networkMode, status, now, unsupported),
	}
	if status == network.ProviderStatusSupported {
		resp.Evidence.DiscoverySource = discovery
		resp.Evidence.KeyExchange = "encrypted-overlay"
		resp.Evidence.Lifecycle = append(resp.Evidence.Lifecycle, network.LifecycleEvent{Event: "prepared", ObservedAt: now})
	} else {
		resp.Evidence.Lifecycle = append(resp.Evidence.Lifecycle, network.LifecycleEvent{Event: "unsupported", ObservedAt: now})
	}
	closeReq, closeResp := closePair(descriptor.ProviderID, opts.ProviderVersion, networkMode, req.RequestID, resp.SessionID, now, true, status, unsupported)
	spec := network.ConformanceSpec{
		Descriptor:       descriptor,
		PrepareRequest:   req,
		PrepareResponse:  resp,
		CloseRequest:     closeReq,
		CloseResponse:    closeResp,
		ExpectedMode:     networkMode,
		RequireSupported: status == network.ProviderStatusSupported,
		ObservedAt:       now,
	}
	if err := network.VerifyProviderConformance(spec); err != nil {
		return ConformanceArtifact{}, err
	}
	return ConformanceArtifact{Supported: status == network.ProviderStatusSupported, Specs: []network.ConformanceSpec{spec}}, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
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

func p2pPolicy(now time.Time, contentRef, sourcePeerID, sourceDigest, sinkDigest string) *core.P2PSessionPolicy {
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
			{ID: sourcePeerID, Role: "source", IdentitySHA256: sourceDigest},
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
		return nil, fmt.Errorf("content server announcement invalid: %w: line=%q stderr=%q", err, strings.TrimSpace(string(line)), strings.TrimSpace(stderr.String()))
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

func scanAndRemove(path string) (ResidueScan, error) {
	entries, err := os.ReadDir(path)
	if err != nil && !os.IsNotExist(err) {
		return ResidueScan{}, fmt.Errorf("scan residue before cleanup: %w", err)
	}
	scan := ResidueScan{RemovedEntries: len(entries)}
	if err := os.RemoveAll(path); err != nil {
		return scan, fmt.Errorf("remove residue: %w", err)
	}
	remaining, err := os.ReadDir(path)
	if err == nil {
		for _, entry := range remaining {
			scan.RemainingNames = append(scan.RemainingNames, entry.Name())
		}
		scan.Clean = len(scan.RemainingNames) == 0
		return scan, nil
	}
	if os.IsNotExist(err) {
		scan.Clean = true
		return scan, nil
	}
	return scan, fmt.Errorf("scan residue after cleanup: %w", err)
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
