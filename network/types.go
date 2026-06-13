package network

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

const (
	ProviderCatalogVersion = "network-provider-contracts.v1"
	SidecarProtocolVersion = "compute-network-sidecar.v1"
)

type ProviderStatus string

const (
	ProviderStatusSupported   ProviderStatus = "supported"
	ProviderStatusDegraded    ProviderStatus = "degraded"
	ProviderStatusUnsupported ProviderStatus = "unsupported"
)

type ProviderCatalog struct {
	Version   string               `json:"version"`
	Providers []ProviderDescriptor `json:"providers"`
}

func (c ProviderCatalog) Validate() error {
	var errs []error
	if c.Version != ProviderCatalogVersion {
		errs = append(errs, fmt.Errorf("version must be %q", ProviderCatalogVersion))
	}
	if len(c.Providers) == 0 {
		errs = append(errs, errors.New("providers is required"))
	}
	seen := map[string]struct{}{}
	for i, provider := range c.Providers {
		if err := provider.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("providers[%d]: %w", i, err))
		}
		key := provider.PluginID + "/" + provider.ProviderID + "/" + provider.ContractID
		if _, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf("providers[%d] duplicates provider identity %q", i, key))
		}
		seen[key] = struct{}{}
	}
	return errors.Join(errs...)
}

type ProviderDescriptor struct {
	ProtocolVersion        string             `json:"protocol_version"`
	PluginID               string             `json:"plugin_id"`
	ProviderID             string             `json:"provider_id"`
	ContractID             string             `json:"contract_id"`
	Version                string             `json:"version"`
	DisplayName            string             `json:"display_name,omitempty"`
	Modes                  []core.NetworkMode `json:"modes"`
	SidecarProtocol        string             `json:"sidecar_protocol"`
	EvidenceSchemaRef      string             `json:"evidence_schema_ref"`
	RequiresDaemon         bool               `json:"requires_daemon"`
	SupportsIngress        bool               `json:"supports_ingress"`
	SupportsContent        bool               `json:"supports_content"`
	ManagedPackageRequired bool               `json:"managed_package_required"`
}

func (d ProviderDescriptor) Validate() error {
	var errs []error
	if d.ProtocolVersion != core.Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", core.Version))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "plugin_id", value: d.PluginID},
		{name: "provider_id", value: d.ProviderID},
		{name: "contract_id", value: d.ContractID},
		{name: "version", value: d.Version},
	} {
		if err := validateToken(field.name, field.value); err != nil {
			errs = append(errs, err)
		}
	}
	if len(d.Modes) == 0 {
		errs = append(errs, errors.New("modes is required"))
	}
	seenModes := map[core.NetworkMode]struct{}{}
	for i, mode := range d.Modes {
		if !validNetworkMode(mode) {
			errs = append(errs, fmt.Errorf("modes[%d] %q is unsupported", i, mode))
		}
		if _, ok := seenModes[mode]; ok {
			errs = append(errs, fmt.Errorf("modes[%d] %q is duplicated", i, mode))
		}
		seenModes[mode] = struct{}{}
	}
	if d.SidecarProtocol != SidecarProtocolVersion {
		errs = append(errs, fmt.Errorf("sidecar_protocol must be %q", SidecarProtocolVersion))
	}
	if !strings.HasPrefix(d.EvidenceSchemaRef, "schema://providers/") {
		errs = append(errs, errors.New("evidence_schema_ref must be a provider schema ref"))
	}
	if !d.ManagedPackageRequired {
		errs = append(errs, errors.New("managed_package_required must be true so hosts keep package/update authority"))
	}
	return errors.Join(errs...)
}

func (d ProviderDescriptor) SupportsMode(mode core.NetworkMode) bool {
	return slices.Contains(d.Modes, mode)
}

type SidecarPrepareRequest struct {
	ProtocolVersion  string                 `json:"protocol_version"`
	RequestID        string                 `json:"request_id"`
	Descriptor       ProviderDescriptor     `json:"descriptor"`
	WorkerID         string                 `json:"worker_id"`
	TaskID           string                 `json:"task_id"`
	LeaseID          string                 `json:"lease_id"`
	OrgID            string                 `json:"org_id"`
	PoolID           string                 `json:"pool_id"`
	RequestedMode    core.NetworkMode       `json:"requested_mode"`
	NetworkPolicy    core.NetworkPolicy     `json:"network_policy"`
	P2PSessionPolicy *core.P2PSessionPolicy `json:"p2p_session_policy,omitempty"`
	AllowedProtocols []string               `json:"allowed_protocols,omitempty"`
}

func (r SidecarPrepareRequest) Validate(now time.Time) error {
	var errs []error
	if r.ProtocolVersion != SidecarProtocolVersion {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", SidecarProtocolVersion))
	}
	if err := r.Descriptor.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("descriptor: %w", err))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "request_id", value: r.RequestID},
		{name: "worker_id", value: r.WorkerID},
		{name: "task_id", value: r.TaskID},
		{name: "lease_id", value: r.LeaseID},
		{name: "org_id", value: r.OrgID},
		{name: "pool_id", value: r.PoolID},
	} {
		if err := validateToken(field.name, field.value); err != nil {
			errs = append(errs, err)
		}
	}
	if !r.Descriptor.SupportsMode(r.RequestedMode) {
		errs = append(errs, fmt.Errorf("requested_mode %q is not supported by descriptor", r.RequestedMode))
	}
	if err := r.NetworkPolicy.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("network_policy: %w", err))
	}
	if r.NetworkPolicy.Mode != "" && r.NetworkPolicy.Mode != r.RequestedMode {
		errs = append(errs, errors.New("network_policy.mode must match requested_mode"))
	}
	if r.RequestedMode == core.NetworkModeP2P {
		if r.P2PSessionPolicy == nil {
			errs = append(errs, errors.New("p2p_session_policy is required for p2p mode"))
		} else if err := r.P2PSessionPolicy.Validate(now); err != nil {
			errs = append(errs, fmt.Errorf("p2p_session_policy: %w", err))
		}
	}
	for i, protocol := range r.AllowedProtocols {
		if err := validateToken(fmt.Sprintf("allowed_protocols[%d]", i), protocol); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type ContentPeer struct {
	PeerID         string   `json:"peer_id"`
	BaseURL        string   `json:"base_url"`
	ContentRefs    []string `json:"content_refs,omitempty"`
	IdentitySHA256 string   `json:"identity_sha256,omitempty"`
}

func (p ContentPeer) Validate() error {
	var errs []error
	if err := validateToken("peer_id", p.PeerID); err != nil {
		errs = append(errs, err)
	}
	parsed, err := url.Parse(p.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		errs = append(errs, errors.New("base_url must be an absolute URL without query or fragment"))
	}
	for i, ref := range p.ContentRefs {
		if !strings.HasPrefix(ref, "artifact://") && !strings.HasPrefix(ref, "content://") {
			errs = append(errs, fmt.Errorf("content_refs[%d] must use artifact:// or content://", i))
		}
	}
	if p.IdentitySHA256 != "" && !validSHA256(p.IdentitySHA256) {
		errs = append(errs, errors.New("identity_sha256 must be sha256:<64 hex chars>"))
	}
	return errors.Join(errs...)
}

type SidecarPrepareResponse struct {
	ProtocolVersion      string                    `json:"protocol_version"`
	RequestID            string                    `json:"request_id"`
	SessionID            string                    `json:"session_id"`
	ProviderID           string                    `json:"provider_id"`
	Mode                 core.NetworkMode          `json:"mode"`
	WorkerID             string                    `json:"worker_id"`
	PeerIDs              []string                  `json:"peer_ids,omitempty"`
	PeerIdentitiesSHA256 map[string]string         `json:"peer_identities_sha256,omitempty"`
	BoundDestinations    []core.NetworkDestination `json:"bound_destinations,omitempty"`
	ContentPeers         []ContentPeer             `json:"content_peers,omitempty"`
	Evidence             ProviderEvidence          `json:"evidence"`
}

func (r SidecarPrepareResponse) ValidateAgainst(req SidecarPrepareRequest, now time.Time) error {
	var errs []error
	if err := req.Validate(now); err != nil {
		errs = append(errs, fmt.Errorf("request: %w", err))
	}
	if r.ProtocolVersion != SidecarProtocolVersion {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", SidecarProtocolVersion))
	}
	if r.RequestID != req.RequestID {
		errs = append(errs, errors.New("request_id must match prepare request"))
	}
	if err := validateToken("session_id", r.SessionID); err != nil {
		errs = append(errs, err)
	}
	if r.ProviderID != req.Descriptor.ProviderID {
		errs = append(errs, errors.New("provider_id must match descriptor"))
	}
	if r.Mode != req.RequestedMode {
		errs = append(errs, errors.New("mode must match requested_mode"))
	}
	if r.WorkerID != req.WorkerID {
		errs = append(errs, errors.New("worker_id must match prepare request"))
	}
	for i, destination := range r.BoundDestinations {
		if err := destination.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("bound_destinations[%d]: %w", i, err))
		}
		if !destinationAllowed(destination, req) {
			errs = append(errs, fmt.Errorf("bound_destinations[%d] expands signed policy", i))
		}
	}
	allowedPeers := p2pPeerIDs(req)
	for i, peerID := range r.PeerIDs {
		if err := validateToken(fmt.Sprintf("peer_ids[%d]", i), peerID); err != nil {
			errs = append(errs, err)
		}
		if len(allowedPeers) > 0 && !slices.Contains(allowedPeers, peerID) {
			errs = append(errs, fmt.Errorf("peer_ids[%d] expands signed peer set", i))
		}
	}
	for peerID, digest := range r.PeerIdentitiesSHA256 {
		if !slices.Contains(r.PeerIDs, peerID) {
			errs = append(errs, fmt.Errorf("peer_identities_sha256[%q] is not in peer_ids", peerID))
		}
		if !validSHA256(digest) {
			errs = append(errs, fmt.Errorf("peer_identities_sha256[%q] must be sha256:<64 hex chars>", peerID))
		}
	}
	for i, peer := range r.ContentPeers {
		if err := peer.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("content_peers[%d]: %w", i, err))
		}
		if len(allowedPeers) > 0 && !slices.Contains(allowedPeers, peer.PeerID) {
			errs = append(errs, fmt.Errorf("content_peers[%d] expands signed peer set", i))
		}
	}
	if err := r.Evidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("evidence: %w", err))
	}
	if r.Evidence.ProviderID != req.Descriptor.ProviderID || r.Evidence.Mode != req.RequestedMode {
		errs = append(errs, errors.New("evidence must match descriptor and requested mode"))
	}
	return errors.Join(errs...)
}

type SidecarCloseRequest struct {
	ProtocolVersion string           `json:"protocol_version"`
	RequestID       string           `json:"request_id"`
	SessionID       string           `json:"session_id"`
	ProviderID      string           `json:"provider_id"`
	Mode            core.NetworkMode `json:"mode"`
	Urgent          bool             `json:"urgent,omitempty"`
	Reason          string           `json:"reason,omitempty"`
}

func (r SidecarCloseRequest) Validate() error {
	var errs []error
	if r.ProtocolVersion != SidecarProtocolVersion {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", SidecarProtocolVersion))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "request_id", value: r.RequestID},
		{name: "session_id", value: r.SessionID},
		{name: "provider_id", value: r.ProviderID},
	} {
		if err := validateToken(field.name, field.value); err != nil {
			errs = append(errs, err)
		}
	}
	if !validNetworkMode(r.Mode) {
		errs = append(errs, fmt.Errorf("mode %q is unsupported", r.Mode))
	}
	if strings.ContainsAny(r.Reason, "\r\n\t\x00") {
		errs = append(errs, errors.New("reason must not contain control characters"))
	}
	return errors.Join(errs...)
}

type SidecarCloseResponse struct {
	ProtocolVersion string           `json:"protocol_version"`
	RequestID       string           `json:"request_id"`
	SessionID       string           `json:"session_id"`
	ProviderID      string           `json:"provider_id"`
	Mode            core.NetworkMode `json:"mode"`
	Closed          bool             `json:"closed"`
	Evidence        ProviderEvidence `json:"evidence"`
}

func (r SidecarCloseResponse) ValidateAgainst(req SidecarCloseRequest) error {
	var errs []error
	if err := req.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("request: %w", err))
	}
	if r.ProtocolVersion != SidecarProtocolVersion {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", SidecarProtocolVersion))
	}
	if r.RequestID != req.RequestID || r.SessionID != req.SessionID ||
		r.ProviderID != req.ProviderID || r.Mode != req.Mode {
		errs = append(errs, errors.New("close response must match close request"))
	}
	if !r.Closed {
		errs = append(errs, errors.New("closed must be true"))
	}
	if err := r.Evidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("evidence: %w", err))
	}
	if req.Urgent && (r.Evidence.UrgentTeardown == nil || !r.Evidence.UrgentTeardown.Completed) {
		errs = append(errs, errors.New("urgent close requires completed urgent teardown evidence"))
	}
	return errors.Join(errs...)
}

type ProviderEvidence struct {
	ProtocolVersion   string            `json:"protocol_version"`
	ProviderID        string            `json:"provider_id"`
	ProviderVersion   string            `json:"provider_version"`
	Mode              core.NetworkMode  `json:"mode"`
	Status            ProviderStatus    `json:"status"`
	OS                string            `json:"os,omitempty"`
	Arch              string            `json:"arch,omitempty"`
	NATPosture        string            `json:"nat_posture,omitempty"`
	DiscoverySource   string            `json:"discovery_source,omitempty"`
	KeyExchange       string            `json:"key_exchange,omitempty"`
	PeerCount         int               `json:"peer_count,omitempty"`
	BytesTx           int64             `json:"bytes_tx,omitempty"`
	BytesRx           int64             `json:"bytes_rx,omitempty"`
	Lifecycle         []LifecycleEvent  `json:"lifecycle,omitempty"`
	UrgentTeardown    *TeardownEvidence `json:"urgent_teardown,omitempty"`
	UnsupportedReason string            `json:"unsupported_reason,omitempty"`
	ArtifactDigest    string            `json:"artifact_digest,omitempty"`
}

func (e ProviderEvidence) Validate() error {
	var errs []error
	if e.ProtocolVersion != core.Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", core.Version))
	}
	if err := validateToken("provider_id", e.ProviderID); err != nil {
		errs = append(errs, err)
	}
	if e.ProviderVersion != "" {
		if err := validateToken("provider_version", e.ProviderVersion); err != nil {
			errs = append(errs, err)
		}
	}
	if !validNetworkMode(e.Mode) {
		errs = append(errs, fmt.Errorf("mode %q is unsupported", e.Mode))
	}
	switch e.Status {
	case ProviderStatusSupported:
		if e.UnsupportedReason != "" {
			errs = append(errs, errors.New("supported evidence must not set unsupported_reason"))
		}
	case ProviderStatusDegraded, ProviderStatusUnsupported:
		if strings.TrimSpace(e.UnsupportedReason) == "" {
			errs = append(errs, errors.New("degraded/unsupported evidence requires unsupported_reason"))
		}
	default:
		errs = append(errs, fmt.Errorf("status %q is unsupported", e.Status))
	}
	if e.PeerCount < 0 || e.BytesTx < 0 || e.BytesRx < 0 {
		errs = append(errs, errors.New("peer and byte counters must be non-negative"))
	}
	if e.ArtifactDigest != "" && !validSHA256(e.ArtifactDigest) {
		errs = append(errs, errors.New("artifact_digest must be sha256:<64 hex chars>"))
	}
	for i, lifecycle := range e.Lifecycle {
		if err := lifecycle.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("lifecycle[%d]: %w", i, err))
		}
	}
	if e.UrgentTeardown != nil {
		if err := e.UrgentTeardown.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("urgent_teardown: %w", err))
		}
	}
	for _, unsafe := range []string{e.NATPosture, e.DiscoverySource, e.KeyExchange, e.UnsupportedReason} {
		if containsUnsafeEvidenceText(unsafe) {
			errs = append(errs, errors.New("evidence text must not contain raw URLs, query strings, bearer tokens, or control characters"))
			break
		}
	}
	return errors.Join(errs...)
}

type LifecycleEvent struct {
	Event      string    `json:"event"`
	ObservedAt time.Time `json:"observed_at"`
	DetailRef  string    `json:"detail_ref,omitempty"`
}

func (e LifecycleEvent) Validate() error {
	var errs []error
	switch e.Event {
	case "prepared", "healthy", "closed", "killed", "unsupported", "degraded":
	case "":
		errs = append(errs, errors.New("event is required"))
	default:
		errs = append(errs, fmt.Errorf("event %q is unsupported", e.Event))
	}
	if e.ObservedAt.IsZero() {
		errs = append(errs, errors.New("observed_at is required"))
	}
	if e.DetailRef != "" && !strings.HasPrefix(e.DetailRef, "evidence://") && !strings.HasPrefix(e.DetailRef, "artifact://") {
		errs = append(errs, errors.New("detail_ref must be an evidence:// or artifact:// ref"))
	}
	return errors.Join(errs...)
}

type TeardownEvidence struct {
	Completed      bool      `json:"completed"`
	ObservedAt     time.Time `json:"observed_at"`
	ProcessStopped bool      `json:"process_stopped"`
	WorkspaceClean bool      `json:"workspace_clean"`
	OpenPeers      int       `json:"open_peers,omitempty"`
	OpenSockets    int       `json:"open_sockets,omitempty"`
}

func (e TeardownEvidence) Validate() error {
	var errs []error
	if e.ObservedAt.IsZero() {
		errs = append(errs, errors.New("observed_at is required"))
	}
	if e.OpenPeers < 0 || e.OpenSockets < 0 {
		errs = append(errs, errors.New("open peer/socket counters must be non-negative"))
	}
	if e.Completed && (!e.ProcessStopped || !e.WorkspaceClean || e.OpenPeers != 0 || e.OpenSockets != 0) {
		errs = append(errs, errors.New("completed teardown requires stopped process, clean workspace, and zero open peer/socket counters"))
	}
	return errors.Join(errs...)
}

func destinationAllowed(destination core.NetworkDestination, req SidecarPrepareRequest) bool {
	for _, allowed := range req.NetworkPolicy.AllowedDestinations {
		if networkDestinationEqual(destination, allowed) {
			return true
		}
	}
	if req.P2PSessionPolicy != nil {
		for _, allowed := range req.P2PSessionPolicy.AllowedDestinations {
			if networkDestinationEqual(destination, allowed) {
				return true
			}
		}
		for _, ref := range req.P2PSessionPolicy.ContentRefs {
			if destination.ContentRef == ref {
				return true
			}
		}
	}
	return false
}

func p2pPeerIDs(req SidecarPrepareRequest) []string {
	if req.P2PSessionPolicy == nil {
		return nil
	}
	ids := make([]string, 0, len(req.P2PSessionPolicy.Peers))
	for _, peer := range req.P2PSessionPolicy.Peers {
		ids = append(ids, peer.ID)
	}
	return ids
}

func networkDestinationEqual(a, b core.NetworkDestination) bool {
	return a.Protocol == b.Protocol && a.Host == b.Host && a.Port == b.Port && a.ContentRef == b.ContentRef
}

func validNetworkMode(mode core.NetworkMode) bool {
	switch mode {
	case core.NetworkModeDirect, core.NetworkModeRelay, core.NetworkModeTailnet, core.NetworkModeTor, core.NetworkModeP2P, core.NetworkModeOffline:
		return true
	default:
		return false
	}
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validateToken(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", name)
	}
	if !tokenPattern.MatchString(value) {
		return fmt.Errorf("%s contains unsupported characters", name)
	}
	return nil
}

func validSHA256(value string) bool {
	return sha256Pattern.MatchString(value)
}

func containsUnsafeEvidenceText(value string) bool {
	lower := strings.ToLower(value)
	return strings.ContainsAny(value, "\r\n\t\x00") ||
		strings.Contains(value, "://") ||
		strings.Contains(value, "?") ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "token=") ||
		strings.Contains(lower, "authorization")
}
