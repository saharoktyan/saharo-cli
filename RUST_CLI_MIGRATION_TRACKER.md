# Rust CLI Migration Tracker

Last updated: 2026-03-03
Scope: migrate `saharo-cli` from Python (Typer) to Rust (`clap`) and switch to k8s-like command model.

## Status Legend

- `DONE` - implemented in Rust and wired to runtime behavior
- `PARTIAL` - implemented for core flow, but not full parity
- `SCAFFOLDED` - command shape exists, handler is placeholder
- `TODO` - not started

## Repository Layout

- active CLI: `rust-cli/`
- active SDK: `rust-sdk/`
- deprecated Python CLI: `deprecated/python-cli/`
- deprecated Python SDK: `deprecated/python-sdk/`

## Target CLI Model (new)

- binary: `saharoctl`
- core resources: `nodes`, `jobs`
- command groups:
  - `join`
  - `get node|nodes|job|jobs`
  - `describe node|job`
  - `delete node`
  - `logs node`

## Current Snapshot

### Already migrated

- `DONE` Rust crate scaffold: `rust-cli/`
- `DONE` Introduced shared Rust SDK crate: `rust-sdk/` (`saharo-sdk`)
- `DONE` `clap` parser + styling + colored output primitives
- `DONE` Working config/auth/settings/health flows in Rust
- `DONE` Added `auth register` (invite claim flow): token claim, password confirmation, token save
- `DONE` `config get` non-interactive path (including AWG config output)
- `DONE` New k8s-like top-level command surface wired in `main.rs`
- `DONE` API client switched to node model and node endpoints (`admin_node_*`, `admin_nodes_list`, `/admin/nodes`, `node_id` filters)
- `DONE` Moved API client core from CLI into SDK (`rust-sdk/src/api.rs`) and wired `rust-cli` through path dependency
- `DONE` Moved reusable node/job domain helpers into SDK (`rust-sdk/src/admin_ops.rs`): `resolve_node_id`, `wait_job`, `resolve_job_node_id_text`
- `DONE` Added typed join request model in SDK (`JoinNodeRequest`) and switched CLI join flow to it
- `DONE` Added typed node/job summary models in SDK and switched `get nodes/get jobs` table rendering to SDK parsers
- `DONE` Added typed node/job details models in SDK and switched `get/describe node|job` flows to SDK parsers
- `DONE` Moved join execution use-case into SDK (`execute_join` with wait options and status propagation)
- `DONE` Moved join request normalization/builder into SDK (`JoinRequestInput` -> `build_join_request`)
- `DONE` Moved admin/join error message mapping into SDK (`format_admin_error`, `format_join_error`)
- `DONE` Added SDK high-level facade (`AdminFacade`) and switched CLI `k8s_cmd` to it for nodes/jobs/join flows
- `DONE` Added SDK `AuthFacade` and switched CLI `auth` flows (`login`, `login-api-key`, `whoami`) to it
- `DONE` Added SDK `AccessFacade` and switched CLI `config get` API calls (`me`, `credentials_ensure`) to it
- `DONE` Added SDK `HealthFacade` and switched CLI hub version check in `health` to it
- `DONE` Added typed `whoami` parser/model in SDK and switched CLI `whoami` data extraction to it (CLI keeps rendering only)
- `DONE` Moved `/version` parsing + CLI compatibility evaluation into SDK (`parse_version_info`, `evaluate_cli_compatibility`) and simplified CLI `health`
- `DONE` Moved `config get` access target resolution (server/protocol selection + validation against `/me`) into SDK (`resolve_access_target_from_me`)
- `DONE` Added typed `/credentials/ensure` request builder in SDK (`CredentialsEnsureInput` -> `build_credentials_ensure_request`) and switched CLI `config get` payload assembly to it
- `DONE` Moved AWG config/URI generation into SDK (`build_awg_conf`, `build_awg_uri`) and removed duplicate AWG builder logic from CLI
- `DONE` Moved AWG keypair/path manager into SDK (`load_or_create_awg_keypair`, `awg_key_dir`) and simplified CLI key handling
- `DONE` Moved `config get` orchestration into SDK `VpnConfigFacade` (target resolution + key handling + credentials ensure + content rendering)
- `DONE` Removed legacy `/admin/agents` client methods from Rust CLI API layer
- `DONE` Removed legacy Rust module `src/servers_cmd.rs`
- `DONE` `get nodes` with table output
- `DONE` `get node` and `describe node`
- `DONE` `get jobs` with table output (`/admin/jobs`)
- `DONE` `get job` and `describe job`
- `DONE` `delete node`
- `DONE` `logs node`
- `PARTIAL` `join` implemented with interactive wizard (mode/auth/sudo prompts), dry-run payload preview, and optional job wait, using `/admin/nodes/join`
- `PARTIAL` Added `join host` bootstrap wizard with broad flag parity and interactive choices (`api/db/admin/root`, enterprise toggle, VPN CIDR, local/SSH install paths, wipe confirm) + `/admin/bootstrap` initialization
- `DONE` Added `services` resource to k8s-like surface:
  - `get services`, `get service`, `describe service`, `delete service`
  - `apply service` (create/update from YAML, optional enable/disable)
  - `reconcile service` (trigger desired-state reconcile on node)
  - `get service-desired` (read node desired-state)
  - `apply service-desired` (replace node desired-state)
  - `update service-desired --mode merge|scale` (append or scale desired-state)
  - `delete service-desired --service ...|--all` (remove entries or clear desired-state)
- `DONE` Added `users` resource to k8s-like surface:
  - `get users`, `get user`, `describe user`
- `DONE` Added `grants` resource to k8s-like surface:
  - `get grants`, `get grant`, `describe grant`
  - `apply grant` (create grant)
  - `delete grant` (revoke grant)
- `DONE` Added `invites` resource to k8s-like surface:
  - `get invites`, `get invite`, `describe invite`
  - `apply invite` (admin create)
- `DONE` Added `releases` resource to k8s-like surface:
  - `get releases`, `get release`, `describe release` (license API)
- `DONE` Added `portal` command group:
  - `portal auth`, `portal profile`, `portal telemetry`, `portal logout`
- `DONE` Added destructive admin utilities in new surface:
  - `delete jobs` (cleanup endpoint)
  - `delete host` (portal license hosts purge)
- `DONE` Expanded `logs`:
  - `logs api` (local Docker)
  - `logs runtime` (runtime container logs via Host API)
- `PARTIAL` Added `update` command group:
  - `DONE` `update cli` (Host API check + atomic self-update on Unix via helper process; `--check-only` for metadata mode)
  - `update host` (trigger Host API update)
  - `DONE` `update nodes` (agent update job fan-out)
  - `DONE` `update service` (rollback to revision)
- `DONE` Added advanced custom-services operations in k8s-like model:
  - `get service-instances`, `get service-revisions`, `get service-events`, `get service-state`, `get service-known`
  - `describe service-drift`
  - `apply service-state`, `apply service-known`
  - `reconcile service --dry-run`
- `DONE` Build verification: `cargo check` passes

### In progress

- `DONE` API model unification in Rust CLI layer: nodes terminology + `/admin/nodes` transport
- `PARTIAL` Interactive join wizard parity vs Python (core flow is ported; orchestration details still simpler)
- `PARTIAL` E2E smoke coverage added via script: `tools/e2e_smoke_rust_cli.sh`

### Not yet migrated

- `TODO` Remove dead legacy API methods from `src/api.rs`
- `PARTIAL` Port remaining product-critical resources to new model (portal/admin utility flows, updates/self flows)
- `TODO` Integration tests for `join/get/describe/delete/logs`
- `DONE` Cargo package/binary name switched to `saharoctl`

## Mapping (old -> new)

| Old Python command | New Rust command |
|---|---|
| `servers list` | `get nodes` |
| `servers get <id>` | `get node <id>` |
| `servers get <id> --verbose`-style detail | `describe node <id>` |
| `servers logs <id>` | `logs node <id>` |
| `servers delete <id>` | `delete node <id>` |
| `servers bootstrap` | `join` |
| `jobs list` | `get jobs` |
| `jobs get <id>` | `get job <id>` |
| detailed job output | `describe job <id>` |

## Acceptance Checklist

- `DONE` `--help` exposes only the new k8s-like command surface (no legacy aliases)
- `TODO` API parity for `join` endpoint in Host API
- `PARTIAL` Stable e2e scenarios for `join -> get nodes -> logs node -> get jobs` (smoke script exists; needs CI/live env wiring)
- `TODO` Release packaging with final binary naming
