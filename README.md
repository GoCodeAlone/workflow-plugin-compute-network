# workflow-plugin-compute-network

Public network provider contracts and conformance helpers for Workflow Compute.

This plugin owns reusable network-provider descriptor, sidecar protocol, and
conformance evidence shapes for captive, P2P, Tor, and tailnet-style providers.
The Workflow Compute host continues to own product admission, leases,
authorization, signed session issuance, daemon launch policy, audit storage,
kill directives, package rollout, and managed-product UX.

## Packages

- `network`: provider descriptors, sidecar prepare/close DTOs, provider evidence
  validation, and conformance helpers.

`network-providers.json` publishes the contract descriptors referenced from
`plugin.json` through `networkProvidersRef`.

## Verification

```sh
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
```

Transport daemons and concrete adapters are intentionally outside this first
contract release. Unsupported evidence prevents false capability advertisement;
it does not complete a supported P2P, Tor, or tailnet claim.

