# workflow-plugin-compute-network

This repo owns public network provider contracts, sidecar DTOs, conformance
helpers, and transport adapter metadata for Workflow Compute.

- Keep host admission, authorization, scheduler state, audit storage, signing
  keys, daemon rollout policy, and managed-product UX out of this repo.
- Reuse `workflow-plugin-compute-core/protocol` network DTOs for task, lease,
  network policy, and P2P session shapes.
- Unsupported provider evidence prevents capability advertisement; it is not a
  supported-mode proof.
- Use `GOWORK=off` for Go commands from the multi-repo workspace.
- Update `plugin.json`, `plugin.contracts.json`, tests, and README with any
  public contract or metadata change.

