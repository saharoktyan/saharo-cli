# Saharo CLI - Roadmap (Pre-Release)

This roadmap tracks the remaining work before the first public release of **Saharo CLI**.
The repository is public primarily for transparency, review, and future contributions.

Scope:
- Saharo CLI (Windows / Linux)
- Host API
- Agent runtime

On-Release (v1.0.0 scope):
- Payment / billing UX
- Sending license key via email
- User account on `portal.saharoktyan.ru`
- Make user-friendly cli installer with PATH integration
- Make cool `readme`
- Add download of selecred version via `portal.saharoktyan.ru`

Post-release (Planned):
- Test CLI on macOS (amd64 / arm64)
- Add new protocols support.
- GUI / Web panel


---

## Status Legend

- DONE - implemented and working
- TODO - planned before release
- FIX - known issue that must be resolved
- VERIFY - implemented but requires validation/testing

---

## Current State (Baseline)

### Implemented
- DONE Versioned CLI binaries published on `portal.saharoktyan.ru`
  - `linux-amd64`
  - `windows-amd64`
- DONE CLI core functionality implemented
- DONE Host API implemented and functional
- DONE Agent runtime implemented and functional
- DONE PyInstaller-based CLI build pipeline
- DONE SSH-based host bootstrap
- DONE SSH-based server (agent) bootstrap
- DONE Protocol bootstrap (xray, awg, etc.)
- DONE Job system (enqueue, execute, status)
- VERIFY License storage in host database (no client-side persistence required)

### Supported Platforms (current)
- CLI:
  - Windows 10 / 11 (amd64)
  - Linux (amd64)
- Host / Agent:
  - Debian 12+
  - Ubuntu 22.04 LTS+

---

## Release Milestones

## M1 - Cross-platform CLI stability
**Goal:** CLI behaves identically and predictably on Windows and Linux.

### Tasks
- TODO Full functional testing on:
  - Windows 10 amd64
  - Windows 11 amd64
  - Linux amd64
- VERIFY Validate PyInstaller builds:
  - no missing modules
  - no hidden-import regressions
  - clean startup (`saharo --help`)
- TODO Validate PATH usage:
  - binary runs correctly from PATH
  - no hardcoded working-directory assumptions
- TODO Verify shell completion behavior:
  - Linux: supported shells
  - Windows: graceful fallback or disable (no crashes)

### Acceptance Criteria
- No unhandled tracebacks during normal CLI usage
- All documented commands execute or fail with meaningful errors

---

## M2 - SSH & bootstrap robustness
**Goal:** Bootstrap flows work reliably across supported systems.

### Tasks
- DONE SSH ControlMaster compatibility detection
- VERIFY SSH multiplexing behavior:
  - Windows 11: enabled
  - Windows 10: fallback to non-mux if incompatible
- TODO Validate SSH flows on:
  - fresh servers
  - servers with existing Saharo installation
- TODO Improve SSH error diagnostics:
  - key not found
  - permission denied
  - unreachable host
  - incompatible OpenSSH versions
- VERIFY host bootstrap detects:
  - closed ports
  - active firewall rules (iptables / ufw)
- VERIFY CLI can:
  - Be updated via installer or cli command
  - Update host
  - Create job for agents update


### Acceptance Criteria
- Host bootstrap never fails due to SSH mux incompatibility
- SSH-related failures are clearly explained
- Closed ports and firewall issues are detected before deployment
- If possible, ports are opened with explicit user confirmation

---

## M3 - Host API & Agent cross-distro validation
**Goal:** Confirm stable behavior across supported Linux distributions.

### Tasks
- TODO Validate host API on:
  - Debian 12
  - Debian 13
  - Ubuntu 22.04 LTS
  - Ubuntu 24.04 LTS
- TODO Validate agent runtime on the same distributions
- TODO Verify Docker + Docker Compose compatibility:
  - compose v2
  - fresh Docker installs
- TODO Verify volume paths, permissions, and persistence

### Acceptance Criteria
- Host API starts and remains healthy
- Agents register and heartbeat reliably
- Protocol services bootstrap correctly

---

## M4 - License handling consistency (FIX)
**Goal:** Eliminate incorrect client-side license assumptions.

### Known Issue

ERR Registry credentials missing.
Re-run saharo host bootstrap with a valid license key,
or login to the registry on the remote host,
or configure registry creds in config.toml.


### Root Cause
- CLI incorrectly checks for license key presence in `config.toml`
- License is already stored in host database after `host bootstrap`
- Agent/protocol bootstrap should rely on host-provided license context

### Tasks
- FIX Remove client-side license key requirement for:
  - `servers bootstrap`
  - `servers protocol bootstrap`
- FIX Ensure license is:
  - resolved by host API
  - passed to agent/protocol bootstrap only when required
- TODO Add explicit error if host has **no valid license**

### Acceptance Criteria
- CLI does not require local license key after successful host bootstrap
- License errors only occur when host-side license is invalid or missing

---

## M5 - End-to-End validation
**Goal:** Confirm full installation flow works without manual intervention.

### Test Scenarios
- TODO Windows CLI → Host bootstrap (fresh server)
- TODO Windows CLI → Server bootstrap
- TODO Windows CLI → Protocol bootstrap
- TODO Linux CLI → Same flow
- TODO Re-run bootstrap with `--force` (idempotent)
- TODO Bootstrap with `--wipe-data` (clean reinstall)

### Acceptance Criteria
- All scenarios complete successfully
- No manual server-side fixes required

---

## M6 - Documentation (Release-grade)
**Goal:** A technically literate user can install Saharo without direct support.

### Tasks
- TODO `README.md` (English, GitHub-style)
  - overview
  - quick start
  - supported platforms
- TODO `docs/quickstart.md`
- TODO `docs/troubleshooting.md`
- TODO `SECURITY.md`
- TODO `CHANGELOG.md` (v1.0.0)

### Acceptance Criteria
- Another person can complete M5 using only documentation

---

## Release Target

**Version:** v1.0.0  
**Release condition:** All milestones M1–M6 satisfied  
**Distribution:** portal.saharoktyan.ru + GitHub Releases

---

## Post-Release (Out of Scope)

- Web panel
- Telegram bot