package network

import (
	"errors"
	"fmt"
	"slices"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

type ConformanceSpec struct {
	Descriptor            ProviderDescriptor     `json:"descriptor"`
	PrepareRequest        SidecarPrepareRequest  `json:"prepare_request"`
	PrepareResponse       SidecarPrepareResponse `json:"prepare_response"`
	CloseRequest          SidecarCloseRequest    `json:"close_request"`
	CloseResponse         SidecarCloseResponse   `json:"close_response"`
	ExpectedMode          core.NetworkMode       `json:"expected_mode"`
	ExpectedContentRefs   []string               `json:"expected_content_refs,omitempty"`
	RequireSupported      bool                   `json:"require_supported,omitempty"`
	RequireLifecycleAudit bool                   `json:"require_lifecycle_audit,omitempty"`
	RequireUrgentTeardown bool                   `json:"require_urgent_teardown,omitempty"`
	ObservedAt            time.Time              `json:"observed_at,omitempty"`
}

func VerifyProviderConformance(spec ConformanceSpec) error {
	now := spec.ObservedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var errs []error
	if err := spec.Descriptor.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("descriptor: %w", err))
	}
	if spec.ExpectedMode == "" {
		spec.ExpectedMode = spec.PrepareRequest.RequestedMode
	}
	if !spec.Descriptor.SupportsMode(spec.ExpectedMode) {
		errs = append(errs, fmt.Errorf("descriptor does not support expected mode %q", spec.ExpectedMode))
	}
	if spec.PrepareRequest.Descriptor.ProviderID != spec.Descriptor.ProviderID ||
		spec.PrepareRequest.Descriptor.ContractID != spec.Descriptor.ContractID {
		errs = append(errs, errors.New("prepare request descriptor must match conformance descriptor"))
	}
	if spec.PrepareRequest.RequestedMode != spec.ExpectedMode {
		errs = append(errs, errors.New("prepare request mode must match expected mode"))
	}
	if err := spec.PrepareResponse.ValidateAgainst(spec.PrepareRequest, now); err != nil {
		errs = append(errs, fmt.Errorf("prepare_response: %w", err))
	}
	if spec.CloseRequest.SessionID != spec.PrepareResponse.SessionID ||
		spec.CloseRequest.ProviderID != spec.Descriptor.ProviderID ||
		spec.CloseRequest.Mode != spec.ExpectedMode {
		errs = append(errs, errors.New("close request must target prepared session"))
	}
	if err := spec.CloseResponse.ValidateAgainst(spec.CloseRequest); err != nil {
		errs = append(errs, fmt.Errorf("close_response: %w", err))
	}
	if spec.RequireSupported && spec.PrepareResponse.Evidence.Status != ProviderStatusSupported {
		errs = append(errs, errors.New("supported conformance requires supported prepare evidence"))
	}
	if !spec.RequireSupported && spec.PrepareResponse.Evidence.Status == ProviderStatusUnsupported {
		if len(spec.PrepareResponse.PeerIDs) != 0 || len(spec.PrepareResponse.BoundDestinations) != 0 || len(spec.PrepareResponse.ContentPeers) != 0 {
			errs = append(errs, errors.New("unsupported evidence must not advertise peers, destinations, or content peers"))
		}
	}
	if spec.RequireLifecycleAudit {
		for _, event := range []string{"prepared", "closed"} {
			if !hasLifecycleEvent(spec.PrepareResponse.Evidence.Lifecycle, event) &&
				!hasLifecycleEvent(spec.CloseResponse.Evidence.Lifecycle, event) {
				errs = append(errs, fmt.Errorf("missing lifecycle event %q", event))
			}
		}
	}
	if spec.RequireUrgentTeardown {
		if !spec.CloseRequest.Urgent {
			errs = append(errs, errors.New("urgent teardown conformance requires urgent close request"))
		}
		if spec.CloseResponse.Evidence.UrgentTeardown == nil || !spec.CloseResponse.Evidence.UrgentTeardown.Completed {
			errs = append(errs, errors.New("urgent teardown conformance requires completed teardown evidence"))
		}
	}
	for _, ref := range spec.ExpectedContentRefs {
		if !contentRefAdvertised(ref, spec.PrepareResponse.ContentPeers) {
			errs = append(errs, fmt.Errorf("expected content ref %q was not advertised by any content peer", ref))
		}
	}
	return errors.Join(errs...)
}

func hasLifecycleEvent(events []LifecycleEvent, event string) bool {
	return slices.ContainsFunc(events, func(candidate LifecycleEvent) bool {
		return candidate.Event == event
	})
}

func contentRefAdvertised(ref string, peers []ContentPeer) bool {
	return slices.ContainsFunc(peers, func(peer ContentPeer) bool {
		return slices.Contains(peer.ContentRefs, ref)
	})
}
