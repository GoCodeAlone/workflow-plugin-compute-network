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
- `transport`: concrete conformance adapters and artifact emission for captive,
  P2P, Tor, and tailnet provider modes.

`network-providers.json` publishes the contract descriptors referenced from
`plugin.json` through `networkProvidersRef`.

## Conformance CLI

The plugin binary can emit sanitized conformance artifacts without requiring a
Workflow Compute host:

```sh
workflow-plugin-compute-network conformance --mode p2p --artifact out/p2p.json
workflow-plugin-compute-network conformance --mode captive --artifact out/captive.json
workflow-plugin-compute-network conformance --mode tor --artifact out/tor.json
workflow-plugin-compute-network conformance --mode tailnet --artifact out/tailnet.json
```

P2P conformance starts a separate local content-server process and transfers
content over HTTP using bounded signed peer identity evidence. Captive
conformance verifies direct, relay, and offline modes deny destinations by
default and leave no residue. Tor and tailnet conformance emit explicit
unsupported evidence when the required local daemon or tool is unavailable, and
unsupported evidence never advertises peers, destinations, or content peers.

## Verification

```sh
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
workflow-plugin-compute-network conformance --mode p2p --artifact out/p2p.json
workflow-plugin-compute-network conformance --mode captive --artifact out/captive.json
```

Unsupported evidence prevents false capability advertisement; it does not
complete a supported Tor or tailnet claim.
