# Saharoctl K8s-like Command Model

Last updated: 2026-03-11

## Principles

- Verb-first UX: `get`, `describe`, `apply`, `delete`, `assign`, `unassign`, `reconcile`, `init`.
- Resource model follows first-class control-plane resources.
- `join host` and `join node` stay separate from workload orchestration.
- Workload lifecycle uses `pods`, `deployments`, `bindings`, not legacy `services`.

## Core Surface

- `auth`
- `settings`
- `health`
- `config`
- `join`
  - `join node`
  - `join host`
- `init`
  - `init role`
- `get`
  - `get nodes|node`
  - `get jobs|job`
  - `get pods|pod`
  - `get deployments|deployment|deployment-revisions`
  - `get bindings|binding`
  - `get users|user`
  - `get roles|role`
  - `get role-bindings|role-binding`
  - `get invites|invite`
  - planned: `get releases|release`
- `describe`
  - `describe node|job|pod|deployment|binding|binding-drift`
  - `describe user|role|role-binding|invite`
- `delete`
  - `delete node|jobs|host`
  - planned: `delete deployment|binding|role|invite`
- `logs`
  - `logs node|api|runtime`
  - planned: `logs job`
- `apply`
  - `apply -f pod.yaml`
  - `apply -f deployment.yaml`
  - `apply -f binding.yaml`
  - `apply -f role.yaml`
  - `apply -f rolebinding.yaml`
- `assign`
  - `assign deployment`
- `unassign`
  - `unassign deployment`
- `reconcile`
  - `reconcile bindings`
- `update`
  - `update host|nodes|cli`

## Legacy Mapping

- `servers bootstrap` -> `join node` / `join host`
- `services apply` -> `apply -f pod.yaml` / `apply -f deployment.yaml`
- `services desired-set` -> `assign deployment`
- `services reconcile` -> `reconcile bindings`
- `services drift` -> `describe binding-drift`
- `jobs *` -> `get/describe job`
- `servers *` -> `get/describe/delete/logs node`

## Rollout Plan

1. Keep only first-class resources in public CLI surface.
2. Port remaining admin utility commands to the same verb-first model.
3. Add integration tests for the full Rust CLI surface.
