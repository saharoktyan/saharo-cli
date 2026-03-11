from __future__ import annotations

from typing import Any, Callable
import os
import platform as platform_mod
import time
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Label, ListItem, ListView, Static
from textual.widgets._input import Input
from textual.widgets._rich_log import RichLog
from rich.text import Text

import httpx
import yaml as pyyaml

from saharo_client import ApiError
from saharo_client.configs import (
    build_awg_conf,
    build_awg_uri,
    resolve_access_target,
)
from saharo_client.errors_utils import parse_api_error_detail
from saharo_client.jobs import normalize_job_type
from saharo_client.resolve import (
    ResolveError,
    resolve_protocol_for_grants,
    resolve_server_id_for_grants,
    resolve_server_id_for_jobs,
    resolve_server_id_for_logs,
    resolve_agent_id_for_logs,
    resolve_agent_id_for_agents,
    resolve_user_id_for_grants,
    resolve_user_id_for_users,
    validate_route_for_protocol,
)
from saharo_client.servers import (
    delete_server as sdk_delete_server,
    detach_server_runtime as sdk_detach_server_runtime,
    fetch_server_logs as sdk_fetch_server_logs,
    get_server_status as sdk_get_server_status,
    get_server_with_protocols as sdk_get_server_with_protocols,
    list_servers_page,
)
from saharo_client.updates import check_updates, host_update, platform_id

from .auth_state import resolve_auth_context
from .compat import cli_protocol, cli_version
from .config import (
    AgentConfig,
    config_path,
    default_config,
    load_config,
    normalize_base_url,
    resolve_license_api_url,
    save_config,
)
from .formatting import format_age, format_list_timestamp
from .http import make_client
from .keys import awg_key_dir, load_or_create_awg_keypair
from .registry_store import delete_registry, load_registry, registry_path
from .semver import is_version_in_range
from .license_resolver import LicenseEntitlementsError, resolve_entitlements
from .commands.host_bootstrap import (
    DEFAULT_INSTALL_DIR,
    DEFAULT_LIC_URL,
    DEFAULT_REGISTRY,
    DEFAULT_TAG,
    host_bootstrap as cli_host_bootstrap,
)
from .commands.servers_cmd import (
    DEFAULT_AGENT_LOOP_INTERVAL_S,
    bootstrap as cli_server_bootstrap,
)
from saharo_client import (
    HostError,
    HttpsContext,
    ensure_https,
    normalize_domain,
    purge_hosts,
    validate_bootstrap_params,
)
from .ssh import SSHSession, SshTarget, build_control_path, is_windows
from .commands.agents_cmd import install_agent as cli_install_agent


class SaharoTUI(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #body {
        height: 1fr;
    }
    #menu {
        width: 24;
        border: tall $primary;
    }
    #content {
        width: 1fr;
        padding: 1;
    }
    #status {
        height: 3;
        padding: 0 1;
    }
    .hidden {
        display: none;
    }
    #servers-output, #servers-logs, #hosts-output, #updates-output, #auth-output, #portal-output, #settings-output,
    #config-output, #users-output, #invites-output, #grants-output, #agents-output, #services-output, #jobs-output,
    #health-output, #self-output {
        padding: 1 0;
    }
    #servers-logs {
        height: 8;
        overflow: auto;
        border: tall $primary;
    }
    #logs-output {
        height: 10;
        overflow: auto;
        border: tall $primary;
    }
    #servers-services, #servers-jobs {
        height: 8;
        overflow: auto;
        border: tall $primary;
    }
    .modal {
        width: 60%;
        max-width: 80;
        border: tall $primary;
        padding: 1 2;
        background: $panel;
    }
    """

    LIC_URL_FIXED = "https://lic.saharoktyan.ru"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "servers_refresh", "Refresh"),
        ("d", "servers_details", "Details"),
        ("s", "servers_status", "Status"),
        ("l", "servers_logs", "Logs"),
        ("x", "servers_detach", "Detach"),
        ("delete", "servers_delete", "Delete"),
        ("t", "servers_tail", "Tail"),
        ("p", "servers_prev", "Prev"),
        ("n", "servers_next", "Next"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._selected_server_id: str | None = None
        self._force_delete: bool = False
        self._servers_page = 1
        self._servers_page_size = 50
        self._servers_pages: int | None = None
        self._server_filter: str | None = None
        self._filter_timer = None
        self._status_timer = None
        self._logs_timer = None
        self._logs_inflight = False
        self._last_logs_at = 0.0
        self._logs_paused = False
        self._status_timer = None
        self._logs_timer = None
        self._selected_user_id: int | None = None
        self._selected_agent_id: int | None = None
        self._selected_grant_id: int | None = None
        self._selected_service_id: int | None = None
        self._selected_job_id: int | None = None
        self._logs_follow_timer = None
        self._logs_follow_mode: str | None = None
        self._logs_follow_target: str | None = None
        self._access_cache: list[dict[str, Any]] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="body"):
            yield ListView(
                ListItem(Label("Servers"), id="menu-servers"),
                ListItem(Label("Hosts"), id="menu-hosts"),
                ListItem(Label("Updates"), id="menu-updates"),
                ListItem(Label("Auth"), id="menu-auth"),
                ListItem(Label("Portal"), id="menu-portal"),
                ListItem(Label("Settings"), id="menu-settings"),
                ListItem(Label("Config"), id="menu-config"),
                ListItem(Label("Users"), id="menu-users"),
                ListItem(Label("Invites"), id="menu-invites"),
                ListItem(Label("Grants"), id="menu-grants"),
                ListItem(Label("Agents"), id="menu-agents"),
                ListItem(Label("Services"), id="menu-services"),
                ListItem(Label("Jobs"), id="menu-jobs"),
                ListItem(Label("Logs"), id="menu-logs"),
                ListItem(Label("Health"), id="menu-health"),
                ListItem(Label("Self"), id="menu-self"),
                id="menu",
            )
            with Vertical(id="content"):
                yield Static("Servers", id="title")
                yield ServersPane(id="servers-section")
                with Vertical(id="hosts-section", classes="hidden"):
                    yield Static("Host update (admin)", id="hosts-title")
                    with Horizontal():
                        yield Button("Bootstrap", id="hosts-bootstrap")
                        yield Button("HTTPS setup", id="hosts-https")
                        yield Button("Purge", id="hosts-purge")
                        yield Button("Trigger host update", id="hosts-update")
                    yield Static("", id="hosts-output")
                with Vertical(id="updates-section", classes="hidden"):
                    yield Static("Update check", id="updates-title")
                    yield Button("Check updates", id="updates-check")
                    yield Static("", id="updates-output")
                with Vertical(id="auth-section", classes="hidden"):
                    yield Static("Auth", id="auth-title")
                    with Horizontal():
                        yield Button("Login", id="auth-login")
                        yield Button("Login API key", id="auth-login-api")
                        yield Button("Logout", id="auth-logout")
                        yield Button("Status", id="auth-status")
                        yield Button("Whoami", id="auth-whoami")
                    yield Static("", id="auth-output")
                with Vertical(id="portal-section", classes="hidden"):
                    yield Static("Portal", id="portal-title")
                    with Horizontal():
                        yield Button("Auth", id="portal-auth")
                        yield Button("Profile", id="portal-profile")
                        yield Button("Telemetry", id="portal-telemetry")
                        yield Button("Logout", id="portal-logout")
                    yield Input(placeholder="License API URL (optional)", id="portal-lic-url")
                    yield Static("", id="portal-output")
                with Vertical(id="settings-section", classes="hidden"):
                    yield Static("Settings", id="settings-title")
                    yield Input(placeholder="Base URL", id="settings-base-url")
                    yield Input(placeholder="License API URL", id="settings-lic-url")
                    yield Checkbox("Force init", id="settings-force")
                    with Horizontal():
                        yield Button("Show", id="settings-show")
                        yield Button("Set", id="settings-set")
                        yield Button("Init", id="settings-init")
                    yield Static("", id="settings-output")
                with Vertical(id="config-section", classes="hidden"):
                    yield Static("Client Config", id="config-title")
                    with Horizontal():
                        yield Button("Load access", id="config-load-access")
                        yield Button("Get config", id="config-get")
                    yield DataTable(id="config-access")
                    yield Input(placeholder="Server id or name (optional)", id="config-server")
                    yield Input(placeholder="Protocol (optional)", id="config-protocol")
                    yield Input(placeholder="Route (tcp/xhttp, optional)", id="config-route")
                    yield Input(placeholder="Device label (optional)", id="config-device")
                    yield Input(placeholder="Output path (optional)", id="config-out")
                    yield Checkbox("AWG conf output", id="config-conf")
                    yield Checkbox("Quiet", id="config-quiet")
                    yield Static("", id="config-output")
                with Vertical(id="users-section", classes="hidden"):
                    yield Static("Users", id="users-title")
                    with Horizontal():
                        yield Button("List", id="users-list")
                        yield Button("Get", id="users-get")
                        yield Button("Freeze", id="users-freeze")
                        yield Button("Unfreeze", id="users-unfreeze")
                        yield Button("Extend", id="users-extend")
                    yield Input(placeholder="Search q (optional)", id="users-q")
                    yield Input(placeholder="Limit (default 50)", id="users-limit")
                    yield Input(placeholder="Offset (default 0)", id="users-offset")
                    yield Input(placeholder="Selected user id (optional)", id="users-id")
                    yield Input(placeholder="Username (optional)", id="users-username")
                    yield Input(placeholder="Freeze reason (optional)", id="users-reason")
                    yield Input(placeholder="Extend days (required for extend)", id="users-days")
                    yield DataTable(id="users-table")
                    yield Static("", id="users-output")
                with Vertical(id="invites-section", classes="hidden"):
                    yield Static("Invites", id="invites-title")
                    with Horizontal():
                        yield Button("Create admin invite", id="invites-create")
                        yield Button("Accept invite", id="invites-accept")
                    yield Static("Admin create", id="invites-admin-title")
                    yield Input(placeholder="Duration days (optional)", id="invites-duration")
                    yield Checkbox("Perpetual", id="invites-perpetual")
                    yield Input(placeholder="Note (optional)", id="invites-note")
                    yield Input(placeholder="Max uses (default 1)", id="invites-max-uses")
                    yield Input(placeholder="Expires in days (default 30)", id="invites-expires")
                    yield Static("User accept", id="invites-user-title")
                    yield Input(placeholder="Invite token", id="invites-token")
                    yield Input(placeholder="Username", id="invites-username")
                    yield Input(placeholder="Password", id="invites-password", password=True)
                    yield Input(placeholder="Confirm password", id="invites-password-confirm", password=True)
                    yield Input(placeholder="Device label (optional)", id="invites-device")
                    yield Static("", id="invites-output")
                with Vertical(id="grants-section", classes="hidden"):
                    yield Static("Grants", id="grants-title")
                    with Horizontal():
                        yield Button("List", id="grants-list")
                        yield Button("Create", id="grants-create")
                        yield Button("Revoke", id="grants-revoke")
                    yield Input(placeholder="Filter user_id (optional)", id="grants-user-filter")
                    yield Input(placeholder="Grant id (for revoke)", id="grants-id")
                    yield Input(placeholder="User (username/id/telegram)", id="grants-user")
                    yield Input(placeholder="User id (optional)", id="grants-user-id")
                    yield Input(placeholder="Server (id or name)", id="grants-server")
                    yield Input(placeholder="Server id (optional)", id="grants-server-id")
                    yield Input(placeholder="Protocol code", id="grants-protocol")
                    yield Input(placeholder="Route (optional)", id="grants-route")
                    yield Input(placeholder="Device limit (optional)", id="grants-device-limit")
                    yield Input(placeholder="Note (optional)", id="grants-note")
                    yield DataTable(id="grants-table")
                    yield Static("", id="grants-output")
                with Vertical(id="agents-section", classes="hidden"):
                    yield Static("Agents", id="agents-title")
                    with Horizontal():
                        yield Button("List", id="agents-list")
                        yield Button("Get", id="agents-get")
                        yield Button("Delete", id="agents-delete")
                        yield Button("Uninstall", id="agents-uninstall")
                        yield Button("Purge", id="agents-purge")
                        yield Button("Create invite", id="agents-create")
                        yield Button("Install", id="agents-install")
                    yield Input(placeholder="Agent id/name (optional)", id="agents-id")
                    yield Input(placeholder="Page (default 1)", id="agents-page")
                    yield Input(placeholder="Page size (default 50)", id="agents-page-size")
                    yield Checkbox("Force", id="agents-force")
                    yield Checkbox("Dry run", id="agents-dry-run")
                    yield Checkbox("Confirm purge", id="agents-confirm-purge")
                    yield Input(placeholder="Invite agent name", id="agents-invite-name")
                    yield Input(placeholder="Invite note (optional)", id="agents-invite-note")
                    yield Input(placeholder="Invite expires minutes (optional)", id="agents-invite-expires")
                    yield DataTable(id="agents-table")
                    yield Static("", id="agents-output")
                with Vertical(id="services-section", classes="hidden"):
                    yield Static("Services", id="services-title")
                    with Horizontal():
                        yield Button("List", id="services-list")
                        yield Button("Add", id="services-add")
                        yield Button("Get", id="services-get")
                        yield Button("Delete", id="services-delete")
                        yield Button("Validate", id="services-validate")
                    yield Checkbox("Enabled only", id="services-enabled-only")
                    yield Input(placeholder="Service code or id (optional)", id="services-code")
                    yield Input(placeholder="YAML file path", id="services-yaml")
                    yield Checkbox("Force delete", id="services-force")
                    yield DataTable(id="services-table")
                    yield Static("", id="services-output")
                with Vertical(id="jobs-section", classes="hidden"):
                    yield Static("Jobs", id="jobs-title")
                    with Horizontal():
                        yield Button("List", id="jobs-list")
                        yield Button("Create", id="jobs-create")
                        yield Button("Get", id="jobs-get")
                        yield Button("Clear", id="jobs-clear")
                    yield Input(placeholder="Status (optional)", id="jobs-status")
                    yield Input(placeholder="Server (id or name, optional)", id="jobs-server")
                    yield Input(placeholder="Agent id (optional)", id="jobs-agent-id")
                    yield Input(placeholder="Page (default 1)", id="jobs-page")
                    yield Input(placeholder="Page size (default 50)", id="jobs-page-size")
                    yield Input(placeholder="Job id (for get/revoke)", id="jobs-id")
                    yield Input(placeholder="Job type (restart-service/start-service/stop-service/restart-container/collect-status/update-agent)", id="jobs-type")
                    yield Input(placeholder="Service name (for service jobs)", id="jobs-service")
                    yield Input(placeholder="Container name (restart-container)", id="jobs-container")
                    yield Input(placeholder="Agent version (update-agent)", id="jobs-version")
                    yield Input(placeholder="Clear older than days", id="jobs-older-than")
                    yield Input(placeholder="Clear status filter", id="jobs-clear-status")
                    yield Input(placeholder="Clear server id", id="jobs-clear-server-id")
                    yield Input(placeholder="Clear agent id", id="jobs-clear-agent-id")
                    yield Checkbox("Dry run", id="jobs-clear-dry")
                    yield Checkbox("Yes (skip confirm)", id="jobs-clear-yes")
                    yield DataTable(id="jobs-table")
                    yield Static("", id="jobs-output")
                with Vertical(id="logs-section", classes="hidden"):
                    yield Static("Logs", id="logs-title")
                    with Horizontal():
                        yield Button("API logs", id="logs-api")
                        yield Button("Agent logs", id="logs-agent")
                        yield Button("Server logs", id="logs-server")
                        yield Button("Stop follow", id="logs-stop")
                    yield Input(placeholder="Agent id/name (for agent logs)", id="logs-agent-id")
                    yield Input(placeholder="Server id/name (for server logs)", id="logs-server-id")
                    yield Input(placeholder="Lines (default 200)", id="logs-lines")
                    yield Checkbox("Follow", id="logs-follow")
                    yield RichLog(id="logs-output", wrap=True, highlight=False, auto_scroll=True)
                with Vertical(id="health-section", classes="hidden"):
                    yield Static("Health", id="health-title")
                    with Horizontal():
                        yield Button("Run health", id="health-run")
                    yield Checkbox("Verbose", id="health-verbose")
                    yield Static("", id="health-output")
                with Vertical(id="self-section", classes="hidden"):
                    yield Static("Self", id="self-title")
                    with Horizontal():
                        yield Button("Update CLI", id="self-update")
                    yield Static("", id="self-output")
        yield Static("", id="status")
        yield Footer()

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def _push_named_screen(self, name: str, callback) -> None:
        screen_cls = globals().get(name)
        if screen_cls is None:
            self._set_status(f"{name} is not available. Reinstall the CLI and retry.")
            return
        self.push_screen(screen_cls(), callback)

    def _val(self, widget_id: str) -> str:
        return (self.query_one(f"#{widget_id}", Input).value or "").strip()

    def _bool(self, widget_id: str) -> bool:
        return bool(self.query_one(f"#{widget_id}", Checkbox).value)

    def _int(self, widget_id: str, default: int | None = None) -> int | None:
        raw = (self.query_one(f"#{widget_id}", Input).value or "").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    def _set_view(self, name: str) -> None:
        sections = {
            "servers": ("Servers", "#servers-section"),
            "hosts": ("Hosts", "#hosts-section"),
            "updates": ("Updates", "#updates-section"),
            "auth": ("Auth", "#auth-section"),
            "portal": ("Portal", "#portal-section"),
            "settings": ("Settings", "#settings-section"),
            "config": ("Config", "#config-section"),
            "users": ("Users", "#users-section"),
            "invites": ("Invites", "#invites-section"),
            "grants": ("Grants", "#grants-section"),
            "agents": ("Agents", "#agents-section"),
            "services": ("Services", "#services-section"),
            "jobs": ("Jobs", "#jobs-section"),
            "logs": ("Logs", "#logs-section"),
            "health": ("Health", "#health-section"),
            "self": ("Self", "#self-section"),
        }
        title = self.query_one("#title", Static)
        for key, (label, selector) in sections.items():
            widget = self.query_one(selector)
            if key == name:
                title.update(label)
                widget.remove_class("hidden")
            else:
                widget.add_class("hidden")
        if name != "servers":
            self._disable_auto_poll()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = (event.item.id or "").replace("menu-", "")
        if item_id in {
            "servers",
            "hosts",
            "updates",
            "auth",
            "portal",
            "settings",
            "config",
            "users",
            "invites",
            "grants",
            "agents",
            "services",
            "jobs",
            "logs",
            "health",
            "self",
        }:
            self._set_view(item_id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "servers-refresh":
            self.run_worker(self._load_servers, thread=True)
        elif event.button.id == "servers-details":
            self.run_worker(self._load_server_details, thread=True)
        elif event.button.id == "servers-status":
            self.run_worker(self._load_server_status, thread=True)
        elif event.button.id == "servers-logs-btn":
            self.run_worker(self._load_server_logs, thread=True)
        elif event.button.id == "servers-detach":
            self.run_worker(self._detach_server, thread=True)
        elif event.button.id == "servers-force-delete":
            self._toggle_force_delete()
        elif event.button.id == "servers-delete":
            self._confirm_delete()
        elif event.button.id == "servers-bootstrap":
            self._push_named_screen("ServerBootstrapWizardScreen", self._on_server_bootstrap_done)
        elif event.button.id == "servers-prev":
            self._prev_page()
        elif event.button.id == "servers-next":
            self._next_page()
        elif event.button.id == "servers-auto-status":
            self._toggle_auto_status()
        elif event.button.id == "servers-auto-logs":
            self._toggle_auto_logs()
        elif event.button.id == "servers-tail":
            self._toggle_tail()
        elif event.button.id == "updates-check":
            self.run_worker(self._check_updates, thread=True)
        elif event.button.id == "hosts-update":
            self.run_worker(self._run_host_update, thread=True)
        elif event.button.id == "hosts-bootstrap":
            self._push_named_screen("HostBootstrapWizardScreen", self._on_bootstrap_done)
        elif event.button.id == "hosts-https":
            self.push_screen(HostHttpsScreen(), self._on_https_done)
        elif event.button.id == "hosts-purge":
            self.push_screen(HostPurgeScreen(), self._on_purge_done)
        elif event.button.id == "auth-login":
            self._push_named_screen("AuthLoginScreen", self._on_auth_login_done)
        elif event.button.id == "auth-login-api":
            self._push_named_screen("AuthApiKeyScreen", self._on_auth_login_api_done)
        elif event.button.id == "auth-logout":
            self._push_named_screen("AuthLogoutScreen", self._on_auth_logout_done)
        elif event.button.id == "auth-status":
            self.run_worker(self._auth_status, thread=True)
        elif event.button.id == "auth-whoami":
            self.run_worker(self._auth_whoami, thread=True)
        elif event.button.id == "portal-auth":
            self._push_named_screen("PortalAuthScreen", self._on_portal_auth_done)
        elif event.button.id == "portal-profile":
            self.run_worker(self._portal_profile, thread=True)
        elif event.button.id == "portal-telemetry":
            self._push_named_screen("PortalTelemetryScreen", self._on_portal_telemetry_done)
        elif event.button.id == "portal-logout":
            self.run_worker(self._portal_logout, thread=True)
        elif event.button.id == "settings-show":
            self.run_worker(self._settings_show, thread=True)
        elif event.button.id == "settings-set":
            self.run_worker(self._settings_set, thread=True)
        elif event.button.id == "settings-init":
            self.run_worker(self._settings_init, thread=True)
        elif event.button.id == "config-load-access":
            self.run_worker(self._config_load_access, thread=True)
        elif event.button.id == "config-get":
            self.run_worker(self._config_get, thread=True)
        elif event.button.id == "users-list":
            self.run_worker(self._users_list, thread=True)
        elif event.button.id == "users-get":
            self.run_worker(self._users_get, thread=True)
        elif event.button.id == "users-freeze":
            self.run_worker(self._users_freeze, thread=True)
        elif event.button.id == "users-unfreeze":
            self.run_worker(self._users_unfreeze, thread=True)
        elif event.button.id == "users-extend":
            self.run_worker(self._users_extend, thread=True)
        elif event.button.id == "invites-create":
            self.run_worker(self._invites_create, thread=True)
        elif event.button.id == "invites-accept":
            self.run_worker(self._invites_accept, thread=True)
        elif event.button.id == "grants-list":
            self.run_worker(self._grants_list, thread=True)
        elif event.button.id == "grants-create":
            self.run_worker(self._grants_create, thread=True)
        elif event.button.id == "grants-revoke":
            self.run_worker(self._grants_revoke, thread=True)
        elif event.button.id == "agents-list":
            self.run_worker(self._agents_list, thread=True)
        elif event.button.id == "agents-get":
            self.run_worker(self._agents_get, thread=True)
        elif event.button.id == "agents-delete":
            self.run_worker(self._agents_delete, thread=True)
        elif event.button.id == "agents-uninstall":
            self.run_worker(self._agents_uninstall, thread=True)
        elif event.button.id == "agents-purge":
            self.run_worker(self._agents_purge, thread=True)
        elif event.button.id == "agents-create":
            self.run_worker(self._agents_create, thread=True)
        elif event.button.id == "agents-install":
            self._push_named_screen("AgentInstallScreen", self._on_agent_install_done)
        elif event.button.id == "services-list":
            self.run_worker(self._services_list, thread=True)
        elif event.button.id == "services-add":
            self.run_worker(self._services_add, thread=True)
        elif event.button.id == "services-get":
            self.run_worker(self._services_get, thread=True)
        elif event.button.id == "services-delete":
            self.run_worker(self._services_delete, thread=True)
        elif event.button.id == "services-validate":
            self.run_worker(self._services_validate, thread=True)
        elif event.button.id == "jobs-list":
            self.run_worker(self._jobs_list, thread=True)
        elif event.button.id == "jobs-create":
            self.run_worker(self._jobs_create, thread=True)
        elif event.button.id == "jobs-get":
            self.run_worker(self._jobs_get, thread=True)
        elif event.button.id == "jobs-clear":
            self.run_worker(self._jobs_clear, thread=True)
        elif event.button.id == "logs-api":
            self.run_worker(self._logs_api, thread=True)
        elif event.button.id == "logs-agent":
            self.run_worker(self._logs_agent, thread=True)
        elif event.button.id == "logs-server":
            self.run_worker(self._logs_server, thread=True)
        elif event.button.id == "logs-stop":
            self._logs_stop_follow()
        elif event.button.id == "health-run":
            self.run_worker(self._health_run, thread=True)
        elif event.button.id == "self-update":
            self.run_worker(self._self_update, thread=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "servers-filter":
            return
        value = (event.value or "").strip()
        self._server_filter = value or None
        self._servers_page = 1
        if self._filter_timer:
            try:
                self._filter_timer.stop()
            except Exception:
                pass
        self._filter_timer = self.set_timer(0.4, self._apply_filter)

    def _apply_filter(self) -> None:
        self.run_worker(self._load_servers, thread=True)

    def on_mount(self) -> None:
        table = self.query_one("#servers-table", DataTable)
        table.add_columns("id", "name", "host", "status", "missed", "last_seen")
        services = self.query_one("#servers-services", DataTable)
        services.add_columns("service", "status", "updated_at", "message")
        jobs = self.query_one("#servers-jobs", DataTable)
        jobs.add_columns("id", "type", "status", "created_at")
        config_access = self.query_one("#config-access", DataTable)
        config_access.add_columns("server_id", "server", "protocol", "status", "expires")
        users_table = self.query_one("#users-table", DataTable)
        users_table.add_columns("id", "username", "role", "telegram_id")
        grants_table = self.query_one("#grants-table", DataTable)
        grants_table.add_columns("id", "user_id", "server_id", "protocol", "status", "expires_at", "revoked_at")
        agents_table = self.query_one("#agents-table", DataTable)
        agents_table.add_columns("id", "name", "status", "missed", "last_seen", "version")
        services_table = self.query_one("#services-table", DataTable)
        services_table.add_columns("id", "code", "display_name", "status", "created")
        jobs_table = self.query_one("#jobs-table", DataTable)
        jobs_table.add_columns("id", "type", "status", "agent_id", "server_id", "created_at", "started_at", "finished_at")
        self._set_view("servers")
        self.run_worker(self._load_servers, thread=True)

    def _load_servers(self) -> None:
        hint = f" (filter: {self._server_filter})" if self._server_filter else ""
        self.call_from_thread(self._set_status, f"Loading servers{hint}...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            page = list_servers_page(
                client,
                page=self._servers_page,
                page_size=self._servers_page_size,
                q=self._server_filter,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()
        self._servers_pages = page.pages
        self.call_from_thread(self._render_servers, page.items)
        pages = page.pages or 1
        self.call_from_thread(self._set_status, f"Servers loaded. page {page.page}/{pages}")

    def _render_servers(self, items: list[dict[str, Any]]) -> None:
        table = self.query_one("#servers-table", DataTable)
        table.clear()
        for s in items or []:
            server_id = str(s.get("id", "-"))
            name = str(s.get("name", "-"))
            host = str(s.get("public_host") or "-")
            status = str(s.get("status") or "-")
            missed_val = s.get("missed_heartbeats")
            missed = "-" if missed_val is None else str(missed_val)
            last_seen = format_list_timestamp(s.get("last_seen_at"))
            if not last_seen and s.get("last_seen_age_s") is not None:
                last_seen = format_age(s.get("last_seen_age_s"))
            table.add_row(
                server_id,
                name,
                host,
                self._style_status(status),
                missed,
                last_seen,
                key=server_id,
            )

    def _require_selected(self) -> str | None:
        if not self._selected_server_id:
            self.call_from_thread(self._set_status, "Select a server first.")
            return None
        return self._selected_server_id

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id
        row_key = str(event.row_key)
        if table_id == "servers-table":
            self._selected_server_id = row_key
            self._set_status(f"Selected server {row_key}.")
            self.query_one("#servers-output", Static).update("")
            self._render_services([])
            self._render_jobs([])
            self._write_logs("")
            self._logs_paused = False
            self.query_one("#servers-tail", Button).label = "Tail: on"
            return
        if table_id == "users-table":
            self._selected_user_id = int(row_key) if row_key.isdigit() else None
            self.query_one("#users-id", Input).value = row_key
            self._set_status(f"Selected user {row_key}.")
            return
        if table_id == "agents-table":
            self._selected_agent_id = int(row_key) if row_key.isdigit() else None
            self.query_one("#agents-id", Input).value = row_key
            self._set_status(f"Selected agent {row_key}.")
            return
        if table_id == "grants-table":
            self._selected_grant_id = int(row_key) if row_key.isdigit() else None
            self.query_one("#grants-id", Input).value = row_key
            self._set_status(f"Selected grant {row_key}.")
            return
        if table_id == "services-table":
            self._selected_service_id = int(row_key) if row_key.isdigit() else None
            self.query_one("#services-code", Input).value = row_key
            self._set_status(f"Selected service {row_key}.")
            return
        if table_id == "jobs-table":
            self._selected_job_id = int(row_key) if row_key.isdigit() else None
            self.query_one("#jobs-id", Input).value = row_key
            self._set_status(f"Selected job {row_key}.")
            return
        if table_id == "config-access":
            # row_key format: server_id|protocol
            if "|" in row_key:
                server_id, protocol = row_key.split("|", 1)
                self.query_one("#config-server", Input).value = server_id
                self.query_one("#config-protocol", Input).value = protocol
                self._set_status(f"Selected access: server {server_id} / {protocol}.")

    def on_mouse_scroll_up(self, event) -> None:
        widget = getattr(event, "widget", None)
        if isinstance(widget, RichLog) and widget.id == "servers-logs" and not widget.is_vertical_scroll_end:
            if not self._logs_paused:
                self._logs_paused = True
                self.query_one("#servers-tail", Button).label = "Tail: off"
                self._set_status("Log tail paused (scroll detected).")

    def on_mouse_scroll_down(self, event) -> None:
        widget = getattr(event, "widget", None)
        if isinstance(widget, RichLog) and widget.id == "servers-logs" and not widget.is_vertical_scroll_end:
            if not self._logs_paused:
                self._logs_paused = True
                self.query_one("#servers-tail", Button).label = "Tail: off"
                self._set_status("Log tail paused (scroll detected).")

    def _load_server_details(self) -> None:
        server_id = self._require_selected()
        if not server_id:
            return
        self.call_from_thread(self._set_status, f"Loading server {server_id} details...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data, protocols = sdk_get_server_with_protocols(client, server_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()

        proto_text = ", ".join(
            f"{p.get('code')}:{p.get('status') or 'unknown'}" for p in protocols if p.get("code")
        )
        lines = [
            f"id: {data.get('id')}",
            f"name: {data.get('name')}",
            f"host: {data.get('public_host') or '-'}",
            f"status: {data.get('status') or '-'}",
            f"runtime_id: {data.get('agent_id') or '-'}",
            f"protocols: {proto_text or '-'}",
        ]
        self.call_from_thread(self.query_one("#servers-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, f"Details loaded for {server_id}.")

    def _load_server_status(self) -> None:
        server_id = self._require_selected()
        if not server_id:
            return
        self.call_from_thread(self._set_status, f"Loading server {server_id} status...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = sdk_get_server_status(client, server_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()

        online = bool(data.get("online"))
        status = data.get("status") or ("online" if online else "offline")
        last_seen = data.get("last_seen_at") or "-"
        lines = [
            f"status: {status}",
            f"online: {online}",
            f"last_seen_at: {last_seen}",
        ]
        self.call_from_thread(self.query_one("#servers-output", Static).update, "\n".join(lines))

        last_status = data.get("last_status") if isinstance(data.get("last_status"), dict) else {}
        services = last_status.get("services") if isinstance(last_status, dict) else None
        jobs = last_status.get("jobs") if isinstance(last_status, dict) else None
        self.call_from_thread(self._render_services, services)
        self.call_from_thread(self._render_jobs, jobs)
        self.call_from_thread(self._set_status, f"Status loaded for {server_id}.")

    def _load_server_logs(self) -> None:
        server_id = self._require_selected()
        if not server_id:
            return
        now = time.monotonic()
        if self._logs_inflight or (now - self._last_logs_at) < 2.0:
            return
        self._logs_inflight = True
        self._last_logs_at = now
        self.call_from_thread(self._set_status, f"Loading server {server_id} logs...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = sdk_fetch_server_logs(client, server_id, lines=200)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()
            self._logs_inflight = False

        logs = data.get("logs") or data.get("raw") or ""
        self.call_from_thread(self._write_logs, logs)
        self.call_from_thread(self._set_status, f"Logs loaded for {server_id}.")

    def _detach_server(self) -> None:
        server_id = self._require_selected()
        if not server_id:
            return
        self.call_from_thread(self._set_status, f"Detaching runtime from {server_id}...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            sid, _data = sdk_detach_server_runtime(client, server_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self._set_status, f"Detached runtime from server {sid}.")
        self.run_worker(self._load_servers, thread=True)

    def _toggle_force_delete(self) -> None:
        self._force_delete = not self._force_delete
        label = "Force: on" if self._force_delete else "Force: off"
        self.query_one("#servers-force-delete", Button).label = label
        self._set_status(f"Force delete is {'ON' if self._force_delete else 'OFF'}.")

    def _confirm_delete(self) -> None:
        server_id = self._require_selected()
        if not server_id:
            return
        self._confirm_delete_id = server_id
        self.push_screen(
            ConfirmDeleteScreen(server_id=server_id, force=self._force_delete),
            self._on_delete_confirmed,
        )

    def _on_delete_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            self._set_status("Delete cancelled.")
            return
        self.run_worker(self._delete_server, thread=True)

    def _delete_server(self) -> None:
        server_id = self._require_selected()
        if not server_id:
            return
        self.call_from_thread(self._set_status, f"Deleting server {server_id}...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            sid, _data = sdk_delete_server(client, server_id, force=self._force_delete)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self._set_status, f"Deleted server {sid}.")
        self.run_worker(self._load_servers, thread=True)

    def _render_services(self, services: list[dict[str, Any]] | None) -> None:
        table = self.query_one("#servers-services", DataTable)
        table.clear()
        for svc in services or []:
            name = str(svc.get("service") or svc.get("name") or svc.get("code") or "-")
            status = str(svc.get("status") or "-")
            updated = str(svc.get("updated_at") or svc.get("last_seen_at") or "-")
            message = str(svc.get("message") or svc.get("detail") or "")
            table.add_row(name, self._style_status(status), updated, message)

    def _render_jobs(self, jobs: list[dict[str, Any]] | None) -> None:
        table = self.query_one("#servers-jobs", DataTable)
        table.clear()
        for job in jobs or []:
            jid = str(job.get("id") or "-")
            jtype = str(job.get("type") or "-")
            status = str(job.get("status") or "-")
            created = str(job.get("created_at") or "-")
            table.add_row(jid, jtype, self._style_status(status), created)

    def _style_status(self, status: str) -> Text:
        text = status or "-"
        norm = text.lower()
        if norm in {"running", "ok", "healthy", "online", "succeeded"}:
            return Text(text, style="green")
        if norm in {"failed", "error", "offline", "stopped"}:
            return Text(text, style="red")
        if norm in {"warning", "degraded", "pending"}:
            return Text(text, style="yellow")
        return Text(text, style="dim")

    def _toggle_auto_status(self) -> None:
        if self._status_timer:
            try:
                self._status_timer.stop()
            except Exception:
                pass
            self._status_timer = None
            self.query_one("#servers-auto-status", Button).label = "Auto status: off"
            self._set_status("Auto status disabled.")
            return
        self._status_timer = self.set_interval(5.0, lambda: self.run_worker(self._load_server_status, thread=True))
        self.query_one("#servers-auto-status", Button).label = "Auto status: on"
        self._set_status("Auto status enabled (5s).")

    def _toggle_auto_logs(self) -> None:
        if self._logs_timer:
            try:
                self._logs_timer.stop()
            except Exception:
                pass
            self._logs_timer = None
            self.query_one("#servers-auto-logs", Button).label = "Auto logs: off"
            self._set_status("Auto logs disabled.")
            return
        self._logs_timer = self.set_interval(5.0, lambda: self.run_worker(self._load_server_logs, thread=True))
        self.query_one("#servers-auto-logs", Button).label = "Auto logs: on"
        self._set_status("Auto logs enabled (5s).")

    def _write_logs(self, text: str) -> None:
        log = self.query_one("#servers-logs", RichLog)
        log.clear()
        if text:
            log.write(text)
        if not self._logs_paused:
            log.scroll_end(animate=False)

    def _toggle_tail(self) -> None:
        self._logs_paused = not self._logs_paused
        label = "Tail: off" if self._logs_paused else "Tail: on"
        self.query_one("#servers-tail", Button).label = label
        self._set_status(f"Log tail is {'PAUSED' if self._logs_paused else 'ON'}.")

    def _prev_page(self) -> None:
        if self._servers_page <= 1:
            self._set_status("Already at first page.")
            return
        self._servers_page -= 1
        self.run_worker(self._load_servers, thread=True)

    def _next_page(self) -> None:
        if self._servers_pages is not None and self._servers_page >= self._servers_pages:
            self._set_status("Already at last page.")
            return
        self._servers_page += 1
        self.run_worker(self._load_servers, thread=True)

    def _disable_auto_poll(self) -> None:
        if self._status_timer:
            try:
                self._status_timer.stop()
            except Exception:
                pass
            self._status_timer = None
            self.query_one("#servers-auto-status", Button).label = "Auto status: off"
        if self._logs_timer:
            try:
                self._logs_timer.stop()
            except Exception:
                pass
            self._logs_timer = None
            self.query_one("#servers-auto-logs", Button).label = "Auto logs: off"
        self._logs_paused = False
        self.query_one("#servers-tail", Button).label = "Tail: on"

    def action_servers_refresh(self) -> None:
        self.run_worker(self._load_servers, thread=True)

    def action_servers_details(self) -> None:
        self.run_worker(self._load_server_details, thread=True)

    def action_servers_status(self) -> None:
        self.run_worker(self._load_server_status, thread=True)

    def action_servers_logs(self) -> None:
        self.run_worker(self._load_server_logs, thread=True)

    def action_servers_detach(self) -> None:
        self.run_worker(self._detach_server, thread=True)

    def action_servers_delete(self) -> None:
        self._confirm_delete()

    def action_servers_tail(self) -> None:
        self._toggle_tail()

    def action_servers_prev(self) -> None:
        self._prev_page()

    def action_servers_next(self) -> None:
        self._next_page()

    def _check_updates(self) -> None:
        self.call_from_thread(self._set_status, "Checking updates...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            result = check_updates(
                client,
                current_version=cli_version(),
                platform=platform_id(),
                refresh_admin=True,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()

        lines: list[str] = []
        if result.mode == "user" and result.cli:
            latest = result.cli.latest or "unknown"
            if result.cli.update_available:
                lines.append(f"CLI update available: {result.cli.current} -> {latest}")
            else:
                lines.append(f"CLI is up to date: {result.cli.current}")
        elif result.admin:
            admin = result.admin
            linked = "linked" if admin.linked is True else "not_linked" if admin.linked is False else "unknown"
            status = admin.status or "unknown"
            lines.append(f"License: {linked} (status={status})")
            latest = admin.latest_versions
            lines.append(
                "Latest versions: host={host} agent={agent} cli={cli}".format(
                    host=latest.get("host") or "-",
                    agent=latest.get("agent") or "-",
                    cli=latest.get("cli") or "-",
                )
            )
            count, limit = admin.installations
            if count is not None or limit is not None:
                limit_label = "inf" if not limit or limit <= 0 else str(limit)
                lines.append(f"Installations: {count or 0} / {limit_label}")
            outdated_count, outdated_total = admin.outdated_agents
            if outdated_count is not None and outdated_total is not None:
                lines.append(f"Outdated agents: {outdated_count} / {outdated_total}")
            if admin.compatibility:
                compat = []
                if admin.compatibility.get("cli"):
                    compat.append(f"cli {admin.compatibility.get('cli')}")
                if admin.compatibility.get("agent"):
                    compat.append(f"agent {admin.compatibility.get('agent')}")
                if compat:
                    lines.append("Compatibility: " + ", ".join(compat))
            lines.append(f"Cache updated: {admin.fetched_at or 'unknown'}")
        else:
            lines.append("Update check returned no data.")

        output = "\n".join(lines)
        self.call_from_thread(self.query_one("#updates-output", Static).update, output)
        self.call_from_thread(self._set_status, "Update check completed.")

    def _run_host_update(self) -> None:
        self.call_from_thread(self._set_status, "Triggering host update...")
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = host_update(client, pull_only=False)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Error: {exc}")
            return
        finally:
            client.close()

        if data.get("ok"):
            msg = "Host update scheduled." if data.get("scheduled") else "Host update triggered."
        else:
            msg = "Host update failed."
        if data.get("stderr"):
            msg = f"{msg}\n{data.get('stderr')}"
        self.call_from_thread(self.query_one("#hosts-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Host update finished.")

    def _on_bootstrap_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Bootstrap cancelled.")
            return
        self.run_worker(lambda: self._run_bootstrap(result), thread=True)

    def _run_bootstrap(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Running host bootstrap...")
        try:
            payload = validate_bootstrap_params(dict(data))
        except HostError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return
        https_after = bool(payload.pop("https_after", False))
        payload.pop("https_domain", None)
        payload.pop("https_email", None)
        payload.pop("https_http01", None)
        payload.pop("https_api_port", None)
        try:
            cli_host_bootstrap(**payload)
        except SystemExit as exc:
            code = getattr(exc, "code", 1) or 0
            if code != 0:
                self.call_from_thread(self._set_status, f"Bootstrap failed (exit {code}).")
                return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Bootstrap failed: {exc}")
            return

        if https_after:
            self.call_from_thread(self._set_status, "Configuring HTTPS...")
            try:
                self._run_https_from_data(data)
            except Exception as exc:
                self.call_from_thread(self._set_status, f"HTTPS setup failed: {exc}")
                return

        self.call_from_thread(self._set_status, "Bootstrap completed.")

    def _on_server_bootstrap_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Server bootstrap cancelled.")
            return
        self.run_worker(lambda: self._run_server_bootstrap(result), thread=True)

    def _run_server_bootstrap(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Running server bootstrap...")
        payload = dict(data)
        try:
            cli_server_bootstrap(**payload)
        except SystemExit as exc:
            code = getattr(exc, "code", 1) or 0
            if code != 0:
                self.call_from_thread(self._set_status, f"Server bootstrap failed (exit {code}).")
                return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Server bootstrap failed: {exc}")
            return
        self.call_from_thread(self._set_status, "Server bootstrap completed.")

    def _run_https_from_data(self, data: dict) -> None:
        domain = data.get("https_domain") or ""
        email = data.get("https_email") or ""
        api_port = int(data.get("https_api_port") or 8010)
        http01 = bool(data.get("https_http01"))
        ssh_host = (data.get("ssh_host") or "").strip()
        ssh_port = int(data.get("ssh_port") or 22)
        ssh_key = (data.get("ssh_key") or "").strip() or None
        ssh_password = (data.get("ssh_password") or "").strip() or None
        ssh_sudo = bool(data.get("ssh_sudo", True))
        if ssh_host:
            target = SshTarget(
                host=ssh_host,
                port=ssh_port,
                key_path=ssh_key,
                password=ssh_password,
                sudo=ssh_sudo,
                dry_run=False,
            )
            session = SSHSession(target=target, control_path=build_control_path(dry_run=False))
            try:
                session.start()
                is_root = session.run("id -u").stdout.strip() == "0"
                ctx = HttpsContext(
                    run=lambda cmd, sudo=False: session.run(cmd, sudo=sudo),
                    run_input=lambda cmd, content, sudo=False: session.run_input(cmd, content, sudo=sudo),
                    allow_sudo=ssh_sudo,
                    is_root=is_root,
                    remote=True,
                )
                ensure_https(domain, email, api_port, http01=http01, ctx=ctx)
            finally:
                session.close()
        else:
            import os
            import subprocess

            def _run_local(cmd: str, sudo: bool = False):
                use_cmd = f"sudo {cmd}" if sudo and os.geteuid() != 0 else cmd
                return subprocess.run(use_cmd, shell=True, text=True, capture_output=True)

            def _run_local_input(cmd: str, content: str, sudo: bool = False):
                use_cmd = f"sudo {cmd}" if sudo and os.geteuid() != 0 else cmd
                return subprocess.run(use_cmd, input=content, shell=True, text=True, capture_output=True)

            ctx = HttpsContext(
                run=_run_local,
                run_input=_run_local_input,
                allow_sudo=True,
                is_root=os.geteuid() == 0,
                remote=False,
            )
            ensure_https(domain, email, api_port, http01=http01, ctx=ctx)

    def _on_https_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("HTTPS setup cancelled.")
            return
        self.run_worker(lambda: self._run_https(result), thread=True)

    def _run_https(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Running HTTPS setup...")
        try:
            self._run_https_from_data(data)
        except Exception as exc:
            self.call_from_thread(self._set_status, f"HTTPS setup failed: {exc}")
            return
        self.call_from_thread(self._set_status, "HTTPS setup completed.")

    def _on_purge_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Purge cancelled.")
            return
        self.run_worker(lambda: self._run_purge(result), thread=True)

    def _run_purge(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Running host purge...")
        cfg = load_config()
        token = (cfg.portal_session_token or "").strip()
        csrf = (cfg.portal_csrf_token or "").strip()
        if not token or not csrf:
            self.call_from_thread(self._set_status, "Portal auth missing. Run: saharo portal auth")
            return
        lic_url = (data.get("lic_url") or resolve_license_api_url(cfg) or "").strip().rstrip("/")
        if not lic_url:
            self.call_from_thread(self._set_status, "License API URL is not configured.")
            return
        license_id = (data.get("license_id") or "").strip()
        if not license_id:
            self.call_from_thread(self._set_status, "License id is required.")
            return
        try:
            purge_hosts(
                lic_url=lic_url,
                license_id=license_id,
                session_token=token,
                csrf_token=csrf,
            )
        except HostError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return
        self.call_from_thread(self._set_status, "Purge completed.")

    def _on_auth_login_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Auth login cancelled.")
            return
        self.run_worker(lambda: self._run_auth_login(result), thread=True)

    def _run_auth_login(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Logging in...")
        cfg = load_config()
        base_url = (data.get("base_url") or "").strip() or None
        client = make_client(cfg, profile=None, base_url_override=base_url)
        try:
            token = client.auth_login(username=data["username"], password=data["password"])
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Login failed: {exc}")
            return
        finally:
            client.close()

        cfg.auth.token = token
        cfg.auth.token_type = "bearer"
        save_path = save_config(cfg)
        self.call_from_thread(self.query_one("#auth-output", Static).update, f"Login successful. Token saved to {save_path}.")
        self.call_from_thread(self._set_status, "Auth login completed.")

    def _on_auth_login_api_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Auth login cancelled.")
            return
        self.run_worker(lambda: self._run_auth_login_api(result), thread=True)

    def _run_auth_login_api(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Logging in with API key...")
        cfg = load_config()
        base_url = (data.get("base_url") or "").strip() or None
        client = make_client(cfg, profile=None, base_url_override=base_url)
        try:
            token = client.auth_api_key(api_key=data["api_key"])
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Login failed: {exc}")
            return
        finally:
            client.close()

        cfg.auth.token = token
        cfg.auth.token_type = "bearer"
        save_path = save_config(cfg)
        self.call_from_thread(self.query_one("#auth-output", Static).update, f"Login successful. Token saved to {save_path}.")
        self.call_from_thread(self._set_status, "Auth login completed.")

    def _on_auth_logout_done(self, result: dict | None) -> None:
        if result is None:
            self._set_status("Logout cancelled.")
            return
        self.run_worker(lambda: self._run_auth_logout(result), thread=True)

    def _run_auth_logout(self, data: dict) -> None:
        def _docker_logout(url: str) -> bool:
            import subprocess
            try:
                result = subprocess.run(["docker", "logout", url], capture_output=True, check=False)
            except FileNotFoundError:
                return False
            if result.returncode == 0:
                return True
            return False

        cfg = load_config()
        ctx = resolve_auth_context()
        cfg.auth.token = ""
        save_path = save_config(cfg)
        msg = f"Token cleared from {save_path}."
        docker = bool(data.get("docker"))
        if ctx.role == "admin":
            creds = load_registry()
            if creds and docker:
                _docker_logout(creds.url)
            if creds:
                delete_registry()
                msg = f"{msg}\nRegistry credentials removed."
        self.call_from_thread(self.query_one("#auth-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Logout completed.")

    def _auth_status(self) -> None:
        cfg = load_config()
        token_state = "(set)" if (cfg.auth.token or "").strip() else "(empty)"
        lines = [f"base_url={cfg.base_url} token={token_state} token_type={cfg.auth.token_type}"]
        creds = load_registry()
        if not creds:
            lines.append("Registry: not activated.")
        else:
            lines.append(f"Registry: {creds.url}")
            lines.append(f"Username: {creds.username}")
            issued_at = creds.issued_at or "-"
            lines.append(f"Issued at: {issued_at}")
            lines.append(f"Registry file: {registry_path()}")
        self.call_from_thread(self.query_one("#auth-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Auth status loaded.")

    def _auth_whoami(self) -> None:
        cfg = load_config()
        if not (cfg.auth.token or "").strip():
            self.call_from_thread(self._set_status, "Not authenticated. Run login first.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            me = client.me()
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to fetch /me: {exc}")
            return
        finally:
            client.close()

        username = me.get("username") or "-"
        role = me.get("role") or "-"
        lines = [f"Username: {username}", f"Role: {role}"]
        sub = me.get("subscription") or {}
        if sub:
            status = sub.get("status") or "active"
            ends_at = sub.get("ends_at")
            days_left = sub.get("days_left")
            details: list[str] = []
            if days_left is not None:
                details.append(f"{days_left} days left")
            elif ends_at is None:
                details.append("perpetual")
            sub_display = f"{status} ({', '.join(details)})" if details else status
        else:
            sub_display = "none"
        lines.append(f"Subscription: {sub_display}")
        access = me.get("access") or []
        if access:
            lines.append("Access:")
            for server in access:
                server_id = server.get("id")
                server_name = server.get("name")
                label = server_name or (f"id={server_id}" if server_id is not None else "-")
                for protocol in server.get("protocols") or []:
                    protocol_key = protocol.get("key") or protocol.get("name") or "-"
                    status = protocol.get("status") or "active"
                    expires_at = protocol.get("expires_at") or "—"
                    lines.append(f"  - {label}: {protocol_key} ({status}) exp={expires_at}")
        else:
            lines.append("Access: none")
        self.call_from_thread(self.query_one("#auth-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Whoami loaded.")

    def _on_portal_auth_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Portal auth cancelled.")
            return
        self.run_worker(lambda: self._run_portal_auth(result), thread=True)

    def _run_portal_auth(self, data: dict) -> None:
        def _extract_error_message(resp: httpx.Response) -> str:
            try:
                payload = resp.json()
            except ValueError:
                return ""
            if isinstance(payload, dict):
                err = payload.get("error")
                if isinstance(err, dict):
                    message = err.get("message")
                    if isinstance(message, str):
                        return message
            return ""

        def _extract_session(resp: httpx.Response) -> tuple[str, str]:
            payload = resp.json() if resp.content else {}
            token = str(payload.get("token") or "").strip()
            csrf = resp.cookies.get("saharo_csrf") or ""
            return token, csrf

        cfg = load_config()
        lic_url_value = (data.get("lic_url") or resolve_license_api_url(cfg) or "").strip().rstrip("/")
        if not lic_url_value:
            self.call_from_thread(self._set_status, "License API URL is not configured.")
            return

        has_account = bool(data.get("has_account"))
        with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
            if has_account:
                login = (data.get("login") or "").strip()
                password = (data.get("password") or "").strip()
                if not login or not password:
                    self.call_from_thread(self._set_status, "Login and password are required.")
                    return
                resp = client.post("/v1/auth/login", json={"login": login, "password": password})
                if resp.status_code == 401:
                    self.call_from_thread(self._set_status, "Username/email or password does not match.")
                    return
                if resp.status_code == 403:
                    message = _extract_error_message(resp)
                    self.call_from_thread(self._set_status, message or "Email not verified.")
                    return
                if resp.status_code >= 400:
                    self.call_from_thread(self._set_status, f"Portal auth failed: HTTP {resp.status_code}")
                    return
                token, csrf = _extract_session(resp)
                if not token:
                    self.call_from_thread(self._set_status, "Portal auth failed: missing session token.")
                    return
                client.headers["X-Session-Token"] = token
                if csrf:
                    client.cookies.set("saharo_csrf", csrf)
                me_resp = client.get("/v1/auth/me")
                if me_resp.status_code >= 400:
                    self.call_from_thread(self._set_status, "Portal auth failed: unable to validate session.")
                    return
                me = me_resp.json() if me_resp.content else {}
                if bool(me.get("is_2fa_enabled")):
                    if not csrf:
                        self.call_from_thread(self._set_status, "Portal auth failed: CSRF token missing.")
                        return
                    otp = (data.get("otp_2fa") or "").strip()
                    if not otp:
                        self.call_from_thread(self._set_status, "2FA enabled: provide OTP in auth screen.")
                        return
                    headers = {"X-CSRF-Token": csrf}
                    start = client.post("/v1/auth/admin/2fa/start", headers=headers)
                    if start.status_code == 403:
                        self.call_from_thread(self._set_status, "Admin access required for 2FA verification.")
                        return
                    if start.status_code >= 400:
                        self.call_from_thread(self._set_status, "Failed to send 2FA code to email.")
                        return
                    verify = client.post("/v1/auth/admin/2fa/verify", headers=headers, json={"otp": otp})
                    if verify.status_code == 401:
                        self.call_from_thread(self._set_status, "Invalid or expired confirmation code.")
                        return
                    if verify.status_code >= 400:
                        self.call_from_thread(self._set_status, "2FA verification failed.")
                        return
                cfg.portal_session_token = token
                cfg.portal_csrf_token = csrf or ""
                save_config(cfg)
                self.call_from_thread(self.query_one("#portal-output", Static).update, "Portal session saved.")
                self.call_from_thread(self._set_status, "Portal auth completed.")
                return

            email = (data.get("email") or "").strip()
            username = (data.get("username") or "").strip()
            password = (data.get("password_reg") or "").strip()
            password_confirm = (data.get("password_confirm") or "").strip()
            if not email or not username or not password:
                self.call_from_thread(self._set_status, "Email, username, and password are required.")
                return
            if password != password_confirm:
                self.call_from_thread(self._set_status, "Passwords do not match.")
                return
            resp = client.post(
                "/v1/auth/register",
                json={
                    "email": email,
                    "username": username,
                    "password": password,
                    "password_confirm": password_confirm,
                },
            )
            if resp.status_code == 409:
                message = _extract_error_message(resp) or "Email or username already exists."
                self.call_from_thread(self._set_status, message)
                return
            if resp.status_code >= 400:
                message = _extract_error_message(resp) or f"Registration failed: HTTP {resp.status_code}"
                self.call_from_thread(self._set_status, message)
                return
            otp = (data.get("otp_email") or "").strip()
            if not otp:
                self.call_from_thread(self._set_status, "Verification code required to complete registration.")
                return
            verify = client.post("/v1/auth/verify-email", json={"login": email, "otp": otp})
            if verify.status_code == 401:
                self.call_from_thread(self._set_status, "Invalid or expired confirmation code.")
                return
            if verify.status_code >= 400:
                message = _extract_error_message(verify) or "Email verification failed."
                self.call_from_thread(self._set_status, message)
                return
            token, csrf = _extract_session(verify)
            if not token:
                self.call_from_thread(self._set_status, "Portal auth failed: missing session token.")
                return
            cfg.portal_session_token = token
            cfg.portal_csrf_token = csrf or ""
            save_config(cfg)
            self.call_from_thread(self.query_one("#portal-output", Static).update, "Account verified and session saved.")
            self.call_from_thread(self._set_status, "Portal registration completed.")

    def _on_portal_telemetry_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Telemetry update cancelled.")
            return
        self.run_worker(lambda: self._run_portal_telemetry(result), thread=True)

    def _run_portal_telemetry(self, data: dict) -> None:
        cfg = load_config()
        lic_url_value = (data.get("lic_url") or resolve_license_api_url(cfg) or "").strip().rstrip("/")
        if not lic_url_value:
            self.call_from_thread(self._set_status, "License API URL is not configured.")
            return

        token = (cfg.portal_session_token or "").strip()
        csrf = (cfg.portal_csrf_token or "").strip()
        if not token:
            self.call_from_thread(self._set_status, "Not authenticated with portal. Run: saharo portal auth")
            return
        enabled = bool(data.get("enabled"))

        with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
            client.headers["X-Session-Token"] = token
            if csrf:
                client.cookies.set("saharo_csrf", csrf)
                client.headers["X-CSRF-Token"] = csrf
            resp = client.post("/v1/account/telemetry", json={"enabled": enabled})
            if resp.status_code in (401, 403):
                self.call_from_thread(self._set_status, "Portal session is invalid or expired.")
                return
            if resp.status_code >= 400:
                self.call_from_thread(self._set_status, f"Portal telemetry change failed: HTTP {resp.status_code}")
                return

        self.call_from_thread(
            self.query_one("#portal-output", Static).update,
            "Telemetry enabled." if enabled else "Telemetry disabled.",
        )
        self.call_from_thread(self._set_status, "Telemetry updated.")

    def _portal_profile(self) -> None:
        cfg = load_config()
        token = (cfg.portal_session_token or "").strip()
        if not token:
            self.call_from_thread(self.query_one("#portal-output", Static).update, "Portal profile: not authenticated.")
            self.call_from_thread(self._set_status, "Portal auth missing.")
            return

        lic_url_value = (self._val("portal-lic-url") or resolve_license_api_url(cfg) or "").strip().rstrip("/")
        if not lic_url_value:
            self.call_from_thread(self._set_status, "License API URL is not configured.")
            return

        with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
            client.headers["X-Session-Token"] = token
            resp = client.get("/v1/auth/me")
            if resp.status_code in (401, 403):
                self.call_from_thread(self._set_status, "Portal session is invalid or expired.")
                return
            if resp.status_code >= 400:
                self.call_from_thread(self._set_status, f"Portal status failed: HTTP {resp.status_code}")
                return
            data = resp.json() if resp.content else {}

            telemetry_payload = {}
            licenses_payload = []
            csrf = (cfg.portal_csrf_token or "").strip()
            if csrf:
                client.cookies.set("saharo_csrf", csrf)
                client.headers["X-CSRF-Token"] = csrf
                telemetry_resp = client.get("/v1/account/telemetry")
                if telemetry_resp.status_code < 400:
                    telemetry_payload = telemetry_resp.json() if telemetry_resp.content else {}
                licenses_resp = client.get("/v1/account/licenses")
                if licenses_resp.status_code < 400:
                    licenses_payload = licenses_resp.json() if licenses_resp.content else []

        username = data.get("username") or "unknown"
        email = data.get("email") or "unknown"
        providers = data.get("linked_providers") or []
        if not isinstance(providers, list):
            providers = []
        github = "enabled" if "github" in providers else "disabled"
        google = "enabled" if "google" in providers else "disabled"
        two_fa = "enabled" if data.get("is_2fa_enabled") else "disabled"
        licenses_count = len(licenses_payload) if isinstance(licenses_payload, list) else 0

        lines = [
            "• Profile info",
            f"  Username: {username}",
            f"  Email: {email}",
            f"  2FA: {two_fa}",
            f"  Social integrations: github={github}, google={google}",
            f"• Provisioned licenses: {licenses_count}",
        ]
        if isinstance(licenses_payload, list) and licenses_payload:
            for lic in licenses_payload:
                if not isinstance(lic, dict):
                    continue
                last4 = str(lic.get("key_last4") or "----")
                status = str(lic.get("status") or "unknown")
                name = str(lic.get("name") or lic.get("notes") or "-")
                lines.append(f"  - ****{last4} | {status} | {name}")
        telemetry = telemetry_payload.get("telemetry") if isinstance(telemetry_payload, dict) else None
        enabled = telemetry.get("enabled") if isinstance(telemetry, dict) else None
        if enabled is True:
            telemetry_status = "enabled"
        elif enabled is False:
            telemetry_status = "disabled"
        else:
            telemetry_status = "unknown"
        lines.append(f"• Telemetry: {telemetry_status}")

        self.call_from_thread(self.query_one("#portal-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Portal profile loaded.")

    def _portal_logout(self) -> None:
        cfg = load_config()
        token = (cfg.portal_session_token or "").strip()
        if not token:
            self.call_from_thread(self.query_one("#portal-output", Static).update, "Portal session: already logged out.")
            self.call_from_thread(self._set_status, "Portal logout done.")
            return

        lic_url_value = (resolve_license_api_url(cfg) or "").strip().rstrip("/")
        if not lic_url_value:
            self.call_from_thread(self._set_status, "License API URL is not configured.")
            return
        csrf = (cfg.portal_csrf_token or "").strip()
        with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
            client.headers["X-Session-Token"] = token
            if csrf:
                client.cookies.set("saharo_csrf", csrf)
                client.headers["X-CSRF-Token"] = csrf
            resp = client.post("/v1/auth/logout")
            if resp.status_code not in (200, 204, 401, 403) and resp.status_code >= 400:
                self.call_from_thread(self._set_status, f"Portal logout failed: HTTP {resp.status_code}")
                return

        cfg.portal_session_token = ""
        cfg.portal_csrf_token = ""
        save_config(cfg)
        self.call_from_thread(self.query_one("#portal-output", Static).update, "Portal session cleared.")
        self.call_from_thread(self._set_status, "Portal logout completed.")

    def _settings_show(self) -> None:
        cfg = load_config()
        self.call_from_thread(lambda: setattr(self.query_one("#settings-base-url", Input), "value", cfg.base_url or ""))
        self.call_from_thread(lambda: setattr(self.query_one("#settings-lic-url", Input), "value", cfg.license_api_url or ""))
        token_state = "(set)" if (cfg.auth.token or "").strip() else "(empty)"
        msg = f"base_url={cfg.base_url} license_api_url={cfg.license_api_url} token={token_state}"
        self.call_from_thread(self.query_one("#settings-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Settings loaded.")

    def _settings_set(self) -> None:
        cfg = load_config()
        base_url = self._val("settings-base-url")
        lic_url = self._val("settings-lic-url")
        if base_url:
            cfg.base_url = normalize_base_url(base_url, warn=True)
        if lic_url:
            cfg.license_api_url = lic_url.strip().rstrip("/")
        saved = save_config(cfg)
        self.call_from_thread(self.query_one("#settings-output", Static).update, f"Settings updated: {saved}")
        self.call_from_thread(self._set_status, "Settings saved.")

    def _settings_init(self) -> None:
        path = config_path()
        force = self._bool("settings-force")
        if os.path.exists(path) and not force:
            self.call_from_thread(self.query_one("#settings-output", Static).update, f"Config already exists: {path}")
            self.call_from_thread(self._set_status, "Settings init skipped.")
            return
        base_url = self._val("settings-base-url")
        if not base_url:
            self.call_from_thread(self._set_status, "Base URL is required.")
            return
        cfg = default_config()
        cfg.base_url = normalize_base_url(base_url, warn=True)
        if not cfg.base_url:
            self.call_from_thread(self._set_status, "Base URL cannot be empty.")
            return
        saved = save_config(cfg)
        self.call_from_thread(self.query_one("#settings-output", Static).update, f"Config written: {saved}")
        self.call_from_thread(self._set_status, "Settings initialized.")

    def _config_load_access(self) -> None:
        self.call_from_thread(self._set_status, "Loading access list...")
        cfg = load_config()
        if not (cfg.auth.token or "").strip():
            self.call_from_thread(self._set_status, "Auth token missing. Run login first.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            me = client.me()
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to fetch /me: {exc}")
            return
        finally:
            client.close()

        access = me.get("access") if isinstance(me, dict) else []
        self._access_cache = access if isinstance(access, list) else []
        table = self.query_one("#config-access", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("server_id", "server", "protocol", "status", "expires")
        for server in self._access_cache:
            server_id = server.get("id")
            server_name = server.get("name") or f"id={server_id}"
            for protocol in server.get("protocols") or []:
                protocol_key = protocol.get("key") or protocol.get("name") or "-"
                status = protocol.get("status") or "active"
                expires_at = protocol.get("expires_at") or "—"
                key = f"{server_id}|{protocol_key}"
                table.add_row(str(server_id), str(server_name), str(protocol_key), str(status), str(expires_at), key=key)
        self.call_from_thread(self.query_one("#config-output", Static).update, "Access loaded.")
        self.call_from_thread(self._set_status, "Access list loaded.")

    def _config_get(self) -> None:
        self.call_from_thread(self._set_status, "Fetching config...")
        cfg = load_config()
        if not (cfg.auth.token or "").strip():
            self.call_from_thread(self._set_status, "Auth token missing. Run login first.")
            return
        server = self._val("config-server") or None
        protocol = self._val("config-protocol") or None
        route = self._val("config-route") or None
        device = self._val("config-device") or None
        out = self._val("config-out") or None
        conf = self._bool("config-conf")
        quiet = self._bool("config-quiet")

        def _default_device_label() -> str:
            import socket
            return socket.gethostname() or "device"

        def _default_output_path(protocol_val: str, server_id: int, device_label: str, *, awg_conf: bool = False) -> str:
            from platformdirs import user_config_dir
            from .config import APP_NAME
            if protocol_val == "awg":
                filename = "config.conf" if awg_conf else "config.uri"
                return os.path.join(awg_key_dir(server_id, device_label), filename)
            base = os.path.join(user_config_dir(APP_NAME), "configs", protocol_val, str(server_id))
            safe_label = device_label.replace("/", "_")
            return os.path.join(base, safe_label, "config.txt")

        device_label = (device or _default_device_label()).strip()
        if not device_label:
            self.call_from_thread(self._set_status, "Device label is required.")
            return

        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            me = client.me()
            access = me.get("access") if isinstance(me, dict) else []
            if not access:
                self.call_from_thread(self._set_status, "No servers or protocols available.")
                return
            if not server or not protocol:
                if self._access_cache is None:
                    self._access_cache = access if isinstance(access, list) else []
                if not server or not protocol:
                    self.call_from_thread(self._set_status, "Select server/protocol or use access table.")
                    return
            try:
                server_id, protocol_key = resolve_access_target(access, server, protocol)
            except ValueError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return

            payload = {
                "server_id": server_id,
                "protocol": protocol_key,
                "device_label": device_label,
            }
            if route is not None:
                route_value = route.strip().lower()
                if route_value not in {"tcp", "xhttp"}:
                    self.call_from_thread(self._set_status, "Route must be one of: tcp, xhttp.")
                    return
                payload["route"] = route_value
            if protocol_key == "awg":
                keypair = load_or_create_awg_keypair(server_id, device_label)
                payload["client_public_key"] = keypair.public_key
            data = client.credentials_ensure(**payload)
        finally:
            client.close()

        config = data.get("config") if isinstance(data, dict) else None
        if not isinstance(config, dict):
            self.call_from_thread(self._set_status, "Unexpected response from server.")
            return

        output_path = out or _default_output_path(
            protocol_key,
            server_id,
            device_label,
            awg_conf=conf if protocol_key == "awg" else False,
        )
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        content = None
        if protocol_key == "awg":
            wg_parts = config.get("wg")
            if not isinstance(wg_parts, dict):
                self.call_from_thread(self._set_status, "Config payload missing WireGuard parts.")
                return
            if conf:
                content = build_awg_conf(private_key=keypair.private_key, wg_parts=wg_parts)
            else:
                content = build_awg_uri(
                    private_key=keypair.private_key,
                    public_key=keypair.public_key,
                    wg_parts=wg_parts,
                    name=f"{server_id}-{device_label}",
                )
        else:
            content = config.get("url")
        if not content:
            self.call_from_thread(self._set_status, "Config payload missing expected content.")
            return

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(str(content).strip() + "\n")
        try:
            os.chmod(output_path, 0o600)
        except OSError:
            pass

        msg = f"Config saved to {output_path}"
        if not quiet:
            msg = f"{msg}\n\n{content}"
        self.call_from_thread(self.query_one("#config-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Config generated.")

    def _users_list(self) -> None:
        cfg = load_config()
        q = self._val("users-q") or None
        limit = self._int("users-limit", 50) or 50
        offset = self._int("users-offset", 0) or 0
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.admin_users_list(q=q, limit=limit, offset=offset)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to list users: {exc}")
            return
        finally:
            client.close()

        items = data.get("items") if isinstance(data, dict) else []
        total = data.get("total") if isinstance(data, dict) else None
        table = self.query_one("#users-table", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("id", "username", "role", "telegram_id")
        for u in items or []:
            user_id = str(u.get("id", "-"))
            username = str(u.get("username") or "-")
            role = str(u.get("role") or "-")
            telegram_id = str(u.get("telegram_id") or "-")
            table.add_row(user_id, username, role, telegram_id, key=user_id)
        summary = f"total={total} limit={limit} offset={offset}" if total is not None else "Loaded users."
        self.call_from_thread(self.query_one("#users-output", Static).update, summary)
        self.call_from_thread(self._set_status, "Users list loaded.")

    def _resolve_user_id(self, client, user_id: int | None, username: str | None) -> int | None:
        if user_id is None and username is None:
            return None
        try:
            return resolve_user_id_for_users(client, user_id, username)
        except ResolveError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return None

    def _users_get(self) -> None:
        cfg = load_config()
        user_id = self._int("users-id", None)
        username = self._val("users-username") or None
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            resolved_id = self._resolve_user_id(client, user_id, username) or user_id
            if resolved_id is None:
                self.call_from_thread(self._set_status, "Select user or enter id/username.")
                return
            user = client.admin_user_get(resolved_id)
            try:
                sub = client.admin_user_subscription_get(resolved_id)
            except ApiError as exc:
                if exc.status_code == 404:
                    sub = None
                else:
                    raise
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to fetch user: {exc}")
            return
        finally:
            client.close()

        lines = [
            f"id: {user.get('id')}",
            f"username: {user.get('username')}",
            f"role: {user.get('role')}",
            f"telegram_id: {user.get('telegram_id')}",
        ]
        if sub:
            status = sub.get("status") or "-"
            ends_at = sub.get("ends_at") or "perpetual"
            days_left = sub.get("days_left")
            lines.append(f"subscription_status: {status}")
            lines.append(f"subscription_ends_at: {ends_at}")
            lines.append(f"subscription_days_left: {days_left if days_left is not None else '-'}")
        else:
            lines.append("subscription: -")
        self.call_from_thread(self.query_one("#users-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "User loaded.")

    def _users_freeze(self) -> None:
        cfg = load_config()
        user_id = self._int("users-id", None)
        username = self._val("users-username") or None
        reason = self._val("users-reason") or None
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            resolved_id = self._resolve_user_id(client, user_id, username) or user_id
            if resolved_id is None:
                self.call_from_thread(self._set_status, "Select user or enter id/username.")
                return
            sub = client.admin_user_freeze(resolved_id, reason=reason)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to freeze user: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#users-output", Static).update, f"User {resolved_id} frozen.")
        self.call_from_thread(self._set_status, "User frozen.")

    def _users_unfreeze(self) -> None:
        cfg = load_config()
        user_id = self._int("users-id", None)
        username = self._val("users-username") or None
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            resolved_id = self._resolve_user_id(client, user_id, username) or user_id
            if resolved_id is None:
                self.call_from_thread(self._set_status, "Select user or enter id/username.")
                return
            sub = client.admin_user_unfreeze(resolved_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to unfreeze user: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#users-output", Static).update, f"User {resolved_id} unfrozen.")
        self.call_from_thread(self._set_status, "User unfrozen.")

    def _users_extend(self) -> None:
        cfg = load_config()
        user_id = self._int("users-id", None)
        username = self._val("users-username") or None
        days = self._int("users-days", None)
        if not days:
            self.call_from_thread(self._set_status, "Extend days is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            resolved_id = self._resolve_user_id(client, user_id, username) or user_id
            if resolved_id is None:
                self.call_from_thread(self._set_status, "Select user or enter id/username.")
                return
            sub = client.admin_user_extend(resolved_id, days=days)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to extend user: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#users-output", Static).update, f"User {resolved_id} extended by {days} days.")
        self.call_from_thread(self._set_status, "User extended.")

    def _invites_create(self) -> None:
        cfg = load_config()
        if not (cfg.auth.token or "").strip():
            self.call_from_thread(self._set_status, "Auth token missing. Run login first.")
            return
        duration_days = self._int("invites-duration", None)
        perpetual = self._bool("invites-perpetual")
        note = self._val("invites-note") or None
        max_uses = self._int("invites-max-uses", 1) or 1
        expires_in_days = self._int("invites-expires", 30)
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.invites_create(
                duration_days=duration_days,
                perpetual=perpetual,
                note=note,
                max_uses=max_uses,
                expires_in_days=expires_in_days,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to create invite: {exc}")
            return
        finally:
            client.close()
        token = data.get("token") if isinstance(data, dict) else None
        msg = f"Invite created: {token}" if token else "Invite created but token missing."
        self.call_from_thread(self.query_one("#invites-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Invite created.")

    def _invites_accept(self) -> None:
        cfg = load_config()
        token = self._val("invites-token")
        username = self._val("invites-username")
        password = self._val("invites-password")
        password_confirm = self._val("invites-password-confirm")
        device_label = self._val("invites-device") or None
        if not token:
            self.call_from_thread(self._set_status, "Invite token cannot be empty.")
            return
        if not username:
            self.call_from_thread(self._set_status, "Username is required.")
            return
        if not password or len(password) < 8:
            self.call_from_thread(self._set_status, "Password must be at least 8 characters.")
            return
        if password != password_confirm:
            self.call_from_thread(self._set_status, "Passwords do not match.")
            return
        if not device_label:
            import socket
            device_label = socket.gethostname() or "device"
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.invites_claim_local(
                token=token,
                username=username,
                password=password,
                device_label=device_label,
                platform=f"{platform_mod.system()} {platform_mod.release()}".strip(),
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Invite claim failed: {exc}")
            return
        finally:
            client.close()
        jwt = data.get("token") if isinstance(data, dict) else None
        if not isinstance(jwt, str) or not jwt:
            self.call_from_thread(self._set_status, "Unexpected response: token missing.")
            return
        cfg.auth.token = jwt
        cfg.auth.token_type = "bearer"
        save_path = save_config(cfg)
        self.call_from_thread(
            self.query_one("#invites-output", Static).update,
            f"Invite accepted. Token saved to {save_path}.",
        )
        self.call_from_thread(self._set_status, "Invite accepted.")

    def _grants_list(self) -> None:
        cfg = load_config()
        user_id = self._int("grants-user-filter", None)
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.admin_grants_list(user_id=user_id)
            items = data.get("items") if isinstance(data, dict) else []
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to list grants: {exc}")
            return
        finally:
            client.close()

        protocol_map = {}
        if items:
            client = make_client(cfg, profile=None, base_url_override=None)
            try:
                proto_data = client.admin_protocols_list()
                for p in proto_data.get("items", []) if isinstance(proto_data, dict) else []:
                    protocol_map[int(p["id"])] = p.get("code") or p.get("title") or str(p.get("id"))
            except ApiError:
                protocol_map = {}
            finally:
                client.close()

        table = self.query_one("#grants-table", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("id", "user_id", "server_id", "protocol", "status", "expires_at", "revoked_at")
        for g in items or []:
            protocol_id = g.get("protocol_id")
            protocol_label = protocol_map.get(int(protocol_id)) if protocol_id is not None else None
            protocol_display = protocol_label or str(protocol_id or "-")
            gid = str(g.get("id", "-"))
            table.add_row(
                gid,
                str(g.get("user_id", "-")),
                str(g.get("server_id", "-")),
                protocol_display,
                str(g.get("status") or "-"),
                str(g.get("expires_at") or "-"),
                str(g.get("revoked_at") or "-"),
                key=gid,
            )
        self.call_from_thread(self.query_one("#grants-output", Static).update, "Grants loaded.")
        self.call_from_thread(self._set_status, "Grants list loaded.")

    def _grants_create(self) -> None:
        cfg = load_config()
        user = self._val("grants-user") or None
        user_id = self._int("grants-user-id", None)
        server = self._val("grants-server") or None
        server_id = self._int("grants-server-id", None)
        protocol = self._val("grants-protocol") or None
        route = self._val("grants-route") or None
        device_limit = self._int("grants-device-limit", None)
        note = self._val("grants-note") or None

        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            try:
                resolved_user_id = resolve_user_id_for_grants(client, user, user_id)
            except ResolveError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return
            try:
                resolved_server_id = resolve_server_id_for_grants(client, server, server_id)
            except ResolveError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return
            try:
                protocol_id, protocol_code = resolve_protocol_for_grants(client, protocol)
            except ResolveError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return
            try:
                resolved_route = validate_route_for_protocol(protocol_code, route)
            except ResolveError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return
            grant = client.admin_grant_create(
                user_id=resolved_user_id,
                server_id=resolved_server_id,
                protocol_id=protocol_id,
                route=resolved_route,
                device_limit=device_limit,
                note=note,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to create grant: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#grants-output", Static).update, f"Grant {grant.get('id')} created.")
        self.call_from_thread(self._set_status, "Grant created.")

    def _grants_revoke(self) -> None:
        cfg = load_config()
        grant_id = self._int("grants-id", None)
        if not grant_id:
            self.call_from_thread(self._set_status, "Grant id is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            grant = client.admin_grant_revoke(grant_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to revoke grant: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#grants-output", Static).update, f"Grant {grant.get('id', grant_id)} revoked.")
        self.call_from_thread(self._set_status, "Grant revoked.")

    def _agents_list(self) -> None:
        cfg = load_config()
        page = self._int("agents-page", 1) or 1
        page_size = self._int("agents-page-size", 50) or 50
        if page < 1 or page_size < 1:
            self.call_from_thread(self._set_status, "Page and page size must be >= 1.")
            return
        offset = (page - 1) * page_size
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.admin_agents_list(include_deleted=False, limit=page_size, offset=offset)
        finally:
            client.close()
        agents = data.get("items") if isinstance(data, dict) else []
        total = data.get("total") if isinstance(data, dict) else None
        table = self.query_one("#agents-table", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("id", "name", "status", "missed", "last_seen", "version")
        for a in agents:
            agent_id = str(a.get("id", "-"))
            name = str(a.get("name", "-"))
            status = str(a.get("status", "-"))
            missed_val = a.get("missed_heartbeats")
            missed = "-" if missed_val is None else str(missed_val)
            age = format_age(a.get("last_seen_age_s"))
            version = str((a.get("meta") or {}).get("version", "-"))
            table.add_row(agent_id, name, status, missed, age, version, key=agent_id)
        summary = f"page={page} total={total}" if total is not None else "Agents loaded."
        self.call_from_thread(self.query_one("#agents-output", Static).update, summary)
        self.call_from_thread(self._set_status, "Agents list loaded.")

    def _agents_get(self) -> None:
        cfg = load_config()
        agent_id_raw = self._val("agents-id")
        if not agent_id_raw:
            self.call_from_thread(self._set_status, "Agent id is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            try:
                agent_id = int(agent_id_raw)
            except ValueError:
                agent_id = resolve_agent_id_for_agents(client, agent_id_raw)
            agent = client.agents_get(agent_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to fetch agent: {exc}")
            return
        except ResolveError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return
        finally:
            client.close()
        lines = [
            f"id: {agent.get('id')}",
            f"name: {agent.get('name')}",
            f"status: {agent.get('status')}",
            f"last_seen_at: {agent.get('last_seen_at')}",
        ]
        meta = agent.get("meta") or {}
        if meta:
            lines.append(f"meta: {meta}")
        last_status = agent.get("last_status")
        if last_status is not None:
            lines.append(f"last_status: {last_status}")
        self.call_from_thread(self.query_one("#agents-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Agent loaded.")

    def _agents_delete(self) -> None:
        cfg = load_config()
        agent_raw = self._val("agents-id")
        force = self._bool("agents-force")
        if not agent_raw:
            self.call_from_thread(self._set_status, "Agent id is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            try:
                agent_id = int(agent_raw)
            except ValueError:
                agent_id = resolve_agent_id_for_agents(client, agent_raw)
            data = client.admin_agent_delete(agent_id, force=force)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to delete agent: {exc}")
            return
        except ResolveError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#agents-output", Static).update, "Agent deleted.")
        self.call_from_thread(self._set_status, "Agent deleted.")

    def _agents_uninstall(self) -> None:
        cfg = load_config()
        agent_raw = self._val("agents-id")
        force = self._bool("agents-force")
        dry_run = self._bool("agents-dry-run")
        if not agent_raw:
            self.call_from_thread(self._set_status, "Agent id is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            try:
                agent_id = int(agent_raw)
            except ValueError:
                agent_id = resolve_agent_id_for_agents(client, agent_raw)
            data = client.admin_agent_uninstall(agent_id, force=force, dry_run=dry_run)
        except ApiError as exc:
            if exc.status_code == 409:
                detail = parse_api_error_detail(exc.details)
                if detail and detail.get("servers"):
                    servers = ", ".join(f"{s.get('id')}:{s.get('name')}" for s in detail["servers"])
                    self.call_from_thread(self._set_status, f"Agent attached to servers: {servers}")
                else:
                    self.call_from_thread(self._set_status, "Agent attached to servers. Use force.")
                return
            self.call_from_thread(self._set_status, f"Failed to uninstall agent: {exc}")
            return
        except ResolveError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return
        finally:
            client.close()
        job_id = data.get("job_id")
        self.call_from_thread(self.query_one("#agents-output", Static).update, f"Uninstall job queued (job_id={job_id}).")
        self.call_from_thread(self._set_status, "Agent uninstall scheduled.")

    def _agents_purge(self) -> None:
        cfg = load_config()
        agent_raw = self._val("agents-id")
        force = self._bool("agents-force")
        dry_run = self._bool("agents-dry-run")
        if not self._bool("agents-confirm-purge"):
            self.call_from_thread(self._set_status, "Enable 'Confirm purge' to proceed.")
            return
        if not agent_raw:
            self.call_from_thread(self._set_status, "Agent id is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            try:
                agent_id = int(agent_raw)
            except ValueError:
                agent_id = resolve_agent_id_for_agents(client, agent_raw)
            data = client.admin_agent_purge(agent_id, force=force, dry_run=dry_run)
        except ApiError as exc:
            if exc.status_code == 409:
                detail = parse_api_error_detail(exc.details)
                if detail and detail.get("servers"):
                    servers = ", ".join(f"{s.get('id')}:{s.get('name')}" for s in detail["servers"])
                    self.call_from_thread(self._set_status, f"Agent attached to servers: {servers}")
                else:
                    self.call_from_thread(self._set_status, "Agent attached to servers. Use force.")
                return
            self.call_from_thread(self._set_status, f"Failed to purge agent: {exc}")
            return
        except ResolveError as exc:
            self.call_from_thread(self._set_status, str(exc))
            return
        finally:
            client.close()
        job_id = data.get("job_id")
        self.call_from_thread(self.query_one("#agents-output", Static).update, f"Purge job queued (job_id={job_id}).")
        self.call_from_thread(self._set_status, "Agent purge scheduled.")

    def _agents_create(self) -> None:
        cfg = load_config()
        name = self._val("agents-invite-name")
        note = self._val("agents-invite-note") or None
        expires = self._int("agents-invite-expires", None)
        if not name:
            self.call_from_thread(self._set_status, "Agent name is required for invite.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.admin_agent_invite_create(name=name, note=note, expires_minutes=expires)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to create invite: {exc}")
            return
        finally:
            client.close()

        invite_id = data.get("id") or data.get("invite_id") or data.get("agent_invite_id")
        token = data.get("token")
        expires_at = data.get("expires_at")
        created_at = data.get("created_at")

        cfg.agents[name] = AgentConfig(
            agent_id=None,
            agent_secret="",
            invite_token=str(token or ""),
            note=note,
            created_at=str(created_at) if created_at else None,
            expires_at=str(expires_at) if expires_at else None,
        )
        save_config(cfg)

        msg = f"Invite {invite_id} token={token} expires={expires_at}"
        self.call_from_thread(self.query_one("#agents-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Agent invite created.")

    def _on_agent_install_done(self, result: dict | None) -> None:
        if not result:
            self._set_status("Agent install cancelled.")
            return
        self.run_worker(lambda: self._run_agent_install(result), thread=True)

    def _run_agent_install(self, data: dict) -> None:
        self.call_from_thread(self._set_status, "Running agent install...")
        try:
            cli_install_agent(**data)
        except SystemExit as exc:
            code = getattr(exc, "code", 1) or 0
            if code != 0:
                self.call_from_thread(self._set_status, f"Agent install failed (exit {code}).")
                return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Agent install failed: {exc}")
            return
        self.call_from_thread(self.query_one("#agents-output", Static).update, "Agent install finished.")
        self.call_from_thread(self._set_status, "Agent install completed.")

    def _services_list(self) -> None:
        cfg = load_config()
        enabled_only = self._bool("services-enabled-only")
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            services = client.admin_custom_services_list(enabled_only=enabled_only)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to list services: {exc}")
            return
        finally:
            client.close()
        table = self.query_one("#services-table", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("id", "code", "display_name", "status", "created")
        for svc in services or []:
            status = "enabled" if svc["enabled"] else "disabled"
            table.add_row(
                str(svc["id"]),
                svc["code"],
                svc["display_name"],
                status,
                format_list_timestamp(svc["created_at"]),
                key=str(svc["id"]),
            )
        self.call_from_thread(self.query_one("#services-output", Static).update, "Services loaded.")
        self.call_from_thread(self._set_status, "Services list loaded.")

    def _services_add(self) -> None:
        yaml_path = self._val("services-yaml")
        if not yaml_path:
            self.call_from_thread(self._set_status, "YAML file path is required.")
            return
        try:
            yaml_content = Path(yaml_path).read_text(encoding="utf-8")
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Failed to read file: {exc}")
            return
        try:
            data = pyyaml.safe_load(yaml_content)
            code = (data.get("name") or "").strip()
            display_name = (data.get("display_name") or code).strip()
            if not code:
                self.call_from_thread(self._set_status, "YAML file must contain a 'name' field.")
                return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Invalid YAML: {exc}")
            return
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            service = client.admin_custom_service_create(
                code=code,
                display_name=display_name,
                yaml_definition=yaml_content,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to add service: {exc}")
            return
        finally:
            client.close()
        msg = f"Service '{code}' added (ID: {service['id']})"
        self.call_from_thread(self.query_one("#services-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Service added.")

    def _services_get(self) -> None:
        code_or_id = self._val("services-code")
        if not code_or_id:
            self.call_from_thread(self._set_status, "Service code or id is required.")
            return
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            if code_or_id.isdigit():
                service = client.admin_custom_service_get(int(code_or_id))
            else:
                service = client.admin_custom_service_get_by_code(code_or_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to get service: {exc}")
            return
        finally:
            client.close()
        lines = [
            f"ID: {service['id']}",
            f"Code: {service['code']}",
            f"Display: {service['display_name']}",
            f"Enabled: {service['enabled']}",
            f"Created: {service['created_at']}",
            f"Updated: {service['updated_at']}",
            "YAML:",
            str(service["yaml_definition"] or ""),
        ]
        self.call_from_thread(self.query_one("#services-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Service loaded.")

    def _services_delete(self) -> None:
        code_or_id = self._val("services-code")
        if not code_or_id:
            self.call_from_thread(self._set_status, "Service code or id is required.")
            return
        if not self._bool("services-force"):
            self.call_from_thread(self._set_status, "Enable 'Force delete' to confirm removal.")
            return
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            if code_or_id.isdigit():
                service = client.admin_custom_service_get(int(code_or_id))
            else:
                service = client.admin_custom_service_get_by_code(code_or_id)
            service_id = service["id"]
            client.admin_custom_service_delete(service_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to delete service: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#services-output", Static).update, f"Service '{service['code']}' removed.")
        self.call_from_thread(self._set_status, "Service deleted.")

    def _services_validate(self) -> None:
        yaml_path = self._val("services-yaml")
        if not yaml_path:
            self.call_from_thread(self._set_status, "YAML file path is required.")
            return
        try:
            yaml_content = Path(yaml_path).read_text(encoding="utf-8")
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Failed to read file: {exc}")
            return
        try:
            import sys
            script_dir = os.path.dirname(os.path.abspath(__file__))
            agent_path = os.path.normpath(os.path.join(script_dir, "../../../../saharo-host-monorepo/http-agent"))
            if os.path.exists(agent_path) and agent_path not in sys.path:
                sys.path.insert(0, agent_path)
            from agent.services.yaml_parser import parse_service_yaml
            definition = parse_service_yaml(yaml_content)
            msg = f"YAML valid: name={definition.name} display={definition.display_name}"
        except ImportError:
            try:
                data = pyyaml.safe_load(yaml_content)
                if not data.get("name"):
                    raise ValueError("Missing 'name' field")
                msg = "Basic YAML structure is valid."
            except Exception as exc:
                self.call_from_thread(self._set_status, f"Validation failed: {exc}")
                return
        except Exception as exc:
            self.call_from_thread(self._set_status, f"Validation failed: {exc}")
            return
        self.call_from_thread(self.query_one("#services-output", Static).update, msg)
        self.call_from_thread(self._set_status, "Service validation completed.")

    def _jobs_list(self) -> None:
        cfg = load_config()
        status = self._val("jobs-status") or None
        server = self._val("jobs-server") or None
        agent_id = self._int("jobs-agent-id", None)
        page = self._int("jobs-page", 1) or 1
        page_size = self._int("jobs-page-size", 50) or 50
        if page < 1 or page_size < 1:
            self.call_from_thread(self._set_status, "Page and page size must be >= 1.")
            return
        offset = (page - 1) * page_size
        server_id = None
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            if server:
                server_id = resolve_server_id_for_jobs(client, server)
            data = client.admin_jobs_list(
                status=status,
                agent_id=agent_id,
                server_id=server_id,
                limit=page_size,
                offset=offset,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to list jobs: {exc}")
            return
        finally:
            client.close()
        items = data.get("items") if isinstance(data, dict) else []
        total = data.get("total") if isinstance(data, dict) else None
        table = self.query_one("#jobs-table", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("id", "type", "status", "agent_id", "server_id", "created_at", "started_at", "finished_at")
        for j in items or []:
            payload = j.get("payload") or {}
            jid = str(j.get("id", "-"))
            table.add_row(
                jid,
                str(j.get("type", "-")),
                str(j.get("status", "-")),
                str(j.get("agent_id", "-")),
                str(payload.get("server_id") or "-"),
                str(j.get("created_at") or "-"),
                str(j.get("started_at") or "-"),
                str(j.get("finished_at") or "-"),
                key=jid,
            )
        summary = f"page={page} total={total}" if total is not None else "Jobs loaded."
        self.call_from_thread(self.query_one("#jobs-output", Static).update, summary)
        self.call_from_thread(self._set_status, "Jobs list loaded.")

    def _jobs_create(self) -> None:
        cfg = load_config()
        job_type = self._val("jobs-type")
        server = self._val("jobs-server") or None
        agent_id = self._int("jobs-agent-id", None)
        service = self._val("jobs-service") or None
        container = self._val("jobs-container") or None
        version = self._val("jobs-version") or None
        if not job_type:
            self.call_from_thread(self._set_status, "Job type is required.")
            return
        job_type_map = {
            "restart-service": "restart_service",
            "start-service": "start_service",
            "stop-service": "stop_service",
            "restart-container": "restart_container",
            "collect-status": "collect_status",
            "update-agent": "agent_update",
        }
        job_key = normalize_job_type(job_type)
        if job_key not in job_type_map:
            self.call_from_thread(self._set_status, "Invalid job type.")
            return
        payload: dict[str, str] = {}
        if job_key in {"restart-service", "start-service", "stop-service"}:
            if not service:
                self.call_from_thread(self._set_status, "Service is required for service jobs.")
                return
            payload["service"] = service
        elif job_key == "restart-container":
            if not container:
                self.call_from_thread(self._set_status, "Container is required for restart-container.")
                return
            payload["container"] = container
        elif job_key == "update-agent":
            if version:
                payload["target_version"] = version

        server_id = None
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            if server:
                server_id = resolve_server_id_for_jobs(client, server)
            if not server_id and not agent_id:
                self.call_from_thread(self._set_status, "Provide server or agent id.")
                return
            if server_id and agent_id:
                self.call_from_thread(self._set_status, "Use either server or agent id, not both.")
                return
            data = client.admin_job_create(
                server_id=server_id,
                agent_id=agent_id,
                job_type=job_type_map[job_key],
                payload=payload,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to create job: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(self.query_one("#jobs-output", Static).update, f"Job created: id={data.get('id')}")
        self.call_from_thread(self._set_status, "Job created.")

    def _jobs_get(self) -> None:
        cfg = load_config()
        job_id = self._int("jobs-id", None)
        if not job_id:
            self.call_from_thread(self._set_status, "Job id is required.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.admin_job_get(job_id)
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to fetch job: {exc}")
            return
        finally:
            client.close()
        lines = [f"{k}: {data.get(k)}" for k in sorted(data.keys())]
        self.call_from_thread(self.query_one("#jobs-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Job loaded.")

    def _jobs_clear(self) -> None:
        cfg = load_config()
        older_than = self._int("jobs-older-than", None)
        status = self._val("jobs-clear-status") or None
        server_id = self._int("jobs-clear-server-id", None)
        agent_id = self._int("jobs-clear-agent-id", None)
        dry_run = self._bool("jobs-clear-dry")
        yes = self._bool("jobs-clear-yes")
        if not yes:
            self.call_from_thread(self._set_status, "Enable 'Yes' checkbox to confirm.")
            return
        client = make_client(cfg, profile=None, base_url_override=None)
        try:
            data = client.admin_jobs_cleanup(
                older_than_days=older_than,
                status=status,
                server_id=server_id,
                agent_id=agent_id,
                dry_run=dry_run,
            )
        except ApiError as exc:
            self.call_from_thread(self._set_status, f"Failed to clear jobs: {exc}")
            return
        finally:
            client.close()
        self.call_from_thread(
            self.query_one("#jobs-output", Static).update,
            f"Matched={data.get('matched')} Deleted={data.get('deleted')}",
        )
        self.call_from_thread(self._set_status, "Jobs cleanup done.")

    def _logs_stop_follow(self) -> None:
        if self._logs_follow_timer:
            try:
                self._logs_follow_timer.stop()
            except Exception:
                pass
            self._logs_follow_timer = None
        self._logs_follow_mode = None
        self._logs_follow_target = None
        self.call_from_thread(self._set_status, "Log follow stopped.")

    def _write_log_output(self, text: str) -> None:
        log = self.query_one("#logs-output", RichLog)
        log.clear()
        if text:
            log.write(text)

    def _logs_api(self) -> None:
        follow = self._bool("logs-follow")
        lines = self._int("logs-lines", 200) or 200

        def _fetch():
            import subprocess
            try:
                res = subprocess.run(["docker", "logs", "--tail", str(lines), "saharo_api"],
                                     text=True, capture_output=True)
            except FileNotFoundError:
                self.call_from_thread(self._set_status, "Docker not found.")
                return
            if res.returncode != 0:
                self.call_from_thread(self._set_status, res.stderr.strip() or "Failed to fetch logs.")
                return
            self.call_from_thread(self._write_log_output, res.stdout.rstrip())

        if follow:
            self._logs_stop_follow()
            self._logs_follow_mode = "api"
            self._logs_follow_target = None
            self._logs_follow_timer = self.set_interval(2.0, lambda: self.run_worker(_fetch, thread=True))
        _fetch()

    def _logs_agent(self) -> None:
        agent_id = self._val("logs-agent-id")
        follow = self._bool("logs-follow")
        lines = self._int("logs-lines", 200) or 200
        if not agent_id:
            self.call_from_thread(self._set_status, "Agent id/name is required.")
            return

        def _fetch():
            cfg = load_config()
            client = make_client(cfg, profile=None, base_url_override=None)
            try:
                agent_id_val = resolve_agent_id_for_logs(client, agent_id)
                result = client.admin_agent_logs(agent_id_val, containers=["saharo_agent"], lines=lines)
            except ApiError as exc:
                self.call_from_thread(self._set_status, f"Failed to fetch logs: {exc}")
                return
            except ResolveError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return
            finally:
                client.close()
            logs = result.get("logs") or {}
            content = str(logs.get("saharo_agent") or "")
            self.call_from_thread(self._write_log_output, content)

        if follow:
            self._logs_stop_follow()
            self._logs_follow_mode = "agent"
            self._logs_follow_target = agent_id
            self._logs_follow_timer = self.set_interval(2.0, lambda: self.run_worker(_fetch, thread=True))
        _fetch()

    def _logs_server(self) -> None:
        server_id = self._val("logs-server-id")
        follow = self._bool("logs-follow")
        lines = self._int("logs-lines", 200) or 200
        if not server_id:
            self.call_from_thread(self._set_status, "Server id/name is required.")
            return

        def _fetch():
            cfg = load_config()
            client = make_client(cfg, profile=None, base_url_override=None)
            try:
                server_id_val = resolve_server_id_for_logs(client, server_id)
                result = client.admin_server_logs(server_id_val, lines=lines)
            except ApiError as exc:
                self.call_from_thread(self._set_status, f"Failed to fetch logs: {exc}")
                return
            except ResolveError as exc:
                self.call_from_thread(self._set_status, str(exc))
                return
            finally:
                client.close()
            logs = result.get("logs") or {}
            combined = []
            for container, content in logs.items():
                combined.append(f"== {container} ==")
                combined.append(str(content or ""))
            self.call_from_thread(self._write_log_output, "\n".join(combined))

        if follow:
            self._logs_stop_follow()
            self._logs_follow_mode = "server"
            self._logs_follow_target = server_id
            self._logs_follow_timer = self.set_interval(2.0, lambda: self.run_worker(_fetch, thread=True))
        _fetch()

    def _health_run(self) -> None:
        cfg = load_config()
        base_url = (cfg.base_url or "").strip()
        current_version = cli_version()
        current_protocol = cli_protocol()
        lines: list[str] = []
        hub_errors: list[str] = []
        if not base_url:
            hub_errors.append("base_url_not_configured")
            lines.append("Hub: base URL not configured.")
        else:
            try:
                client = make_client(cfg, profile=None, base_url_override=None)
                data = client.version()
                client.close()
                api_protocol = data.get("api_protocol")
                supported_range = str(data.get("supported_cli_range") or "").strip()
                api_version = str(data.get("api_version") or data.get("version") or "").strip()
                incompatible = False
                if api_protocol is not None and int(api_protocol) != int(current_protocol):
                    hub_errors.append("cli_protocol_incompatible")
                    lines.append(f"Hub: incompatible protocol (requires {api_protocol}, current {current_protocol}).")
                    incompatible = True
                if supported_range and not is_version_in_range(current_version, supported_range):
                    hub_errors.append("cli_version_incompatible")
                    lines.append(f"Hub: incompatible CLI version (requires {supported_range}, current {current_version}).")
                    incompatible = True
                if not incompatible:
                    lines.append("Hub: compatibility check passed.")
                lines.append(f"Hub: api_version={api_version} api_protocol={api_protocol} supported={supported_range}")
            except Exception as exc:
                hub_errors.append("hub_version_request_failed")
                lines.append(f"Hub: /version check failed: {exc}")

        registry = load_registry()
        license_key = registry.license_key if registry else None
        lic_url = resolve_license_api_url(cfg)
        license_errors: list[str] = []
        if not license_key:
            license_errors.append("license_key_missing")
            lines.append("License: key missing in registry store.")
        elif lic_url:
            entitlements_endpoint = f"{lic_url.rstrip('/')}/v1/entitlements"
            try:
                resp = httpx.get(
                    entitlements_endpoint,
                    headers={"X-License-Key": license_key},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    allowed_major = data.get("allowed_major")
                    resolved = data.get("resolved_versions") or {}
                    lines.append(f"License: OK (allowed_major={allowed_major} resolved={resolved}).")
                else:
                    license_errors.append(f"entitlements_http_{resp.status_code}")
                    lines.append(f"License: entitlements HTTP {resp.status_code}.")
            except Exception as exc:
                license_errors.append("entitlements_request_failed")
                lines.append(f"License: entitlements check failed: {exc}")

            updates_endpoint = f"{lic_url.rstrip('/')}/v1/updates/cli"
            try:
                platform_id = f"{platform_mod.system().lower()}-{platform_mod.machine().lower()}"
                resp = httpx.get(
                    updates_endpoint,
                    params={"current": current_version, "platform": platform_id},
                    headers={"X-License-Key": license_key},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("update_available"):
                        lines.append(f"Updates: available {data.get('latest')} (current {data.get('current')}).")
                    else:
                        lines.append("Updates: CLI is up to date.")
                else:
                    license_errors.append(f"updates_http_{resp.status_code}")
                    lines.append(f"Updates: check skipped (HTTP {resp.status_code}).")
            except Exception as exc:
                license_errors.append("updates_request_failed")
                lines.append(f"Updates: check failed: {exc}")
        else:
            license_errors.append("license_api_url_missing")
            lines.append("License: API URL not configured.")

        self.call_from_thread(self.query_one("#health-output", Static).update, "\n".join(lines))
        self.call_from_thread(self._set_status, "Health check done.")

    def _self_update(self) -> None:
        from .commands.self_cmd import update_self
        try:
            update_self()
        except SystemExit as exc:
            code = getattr(exc, "code", 0) or 0
            if code != 0:
                self.call_from_thread(self._set_status, f"Self update failed (exit {code}).")
                return
        self.call_from_thread(self.query_one("#self-output", Static).update, "Self update completed.")
        self.call_from_thread(self._set_status, "Self update finished.")


class ServersPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter servers (name or host)...", id="servers-filter")
        yield DataTable(id="servers-table")
        with Horizontal():
            yield Button("Refresh", id="servers-refresh")
            yield Button("Prev", id="servers-prev")
            yield Button("Next", id="servers-next")
            yield Button("Details", id="servers-details")
            yield Button("Status", id="servers-status")
            yield Button("Logs", id="servers-logs-btn")
            yield Button("Tail: on", id="servers-tail")
            yield Button("Bootstrap", id="servers-bootstrap")
            yield Button("Detach", id="servers-detach")
            yield Button("Force: off", id="servers-force-delete")
            yield Button("Delete", id="servers-delete")
            yield Button("Auto status: off", id="servers-auto-status")
            yield Button("Auto logs: off", id="servers-auto-logs")
        yield Static("", id="servers-output")
        yield DataTable(id="servers-services")
        yield DataTable(id="servers-jobs")
        yield RichLog(id="servers-logs", wrap=True, highlight=False, auto_scroll=True)

class ConfirmDeleteScreen(ModalScreen[bool]):
    def __init__(self, *, server_id: str, force: bool) -> None:
        super().__init__()
        self._server_id = server_id
        self._force = force

    def compose(self) -> ComposeResult:
        text = f"Delete server {self._server_id}?"
        if self._force:
            text += " (force enabled)"
        with Vertical(classes="modal"):
            yield Static(text)
            with Horizontal():
                yield Button("Cancel", id="confirm-cancel")
                yield Button("Delete", id="confirm-ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm-ok":
            self.dismiss(True)
        else:
            self.dismiss(False)


class HostBootstrapScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal"):
            yield Static("Host bootstrap")
            yield Input(placeholder="API URL (https://api.example.com)", id="hb-api-url")
            yield Input(placeholder="Host name (default: Host API)", id="hb-host-name")
            yield Input(placeholder="X-Root-Secret", id="hb-x-root-secret", password=True)
            yield Input(placeholder="DB password", id="hb-db-password", password=True)
            yield Input(placeholder="Admin username", id="hb-admin-username")
            yield Input(placeholder="Admin password", id="hb-admin-password", password=True)
            yield Input(placeholder="Admin API key name (default: root)", id="hb-admin-api-key")
            yield Input(placeholder="Telegram bot token (optional)", id="hb-telegram-token")
            yield Input(placeholder=f"Install dir (default: {DEFAULT_INSTALL_DIR})", id="hb-install-dir")
            yield Input(placeholder=f"Registry (default: {DEFAULT_REGISTRY})", id="hb-registry")
            yield Input(placeholder=f"Tag (default: {DEFAULT_TAG})", id="hb-tag")
            yield Input(placeholder="Version (optional)", id="hb-version")
            yield Input(placeholder=f"License API URL (default: {DEFAULT_LIC_URL})", id="hb-lic-url")
            yield Input(placeholder="License key", id="hb-license-key", password=True)
            yield Checkbox("No license (use tag/version)", id="hb-no-license")
            yield Checkbox("Force registry password rotation", id="hb-force-registry-password", value=True)
            yield Checkbox("Skip HTTPS during bootstrap", id="hb-skip-https")
            yield Checkbox("Setup HTTPS after bootstrap", id="hb-https-after")
            yield Input(placeholder="HTTPS domain (if enabled)", id="hb-https-domain")
            yield Input(placeholder="HTTPS email (if enabled)", id="hb-https-email")
            yield Checkbox("HTTPS HTTP-01 challenge", id="hb-https-http01", value=True)
            yield Input(placeholder="HTTPS API port (default: 8010)", id="hb-https-api-port")
            yield Input(placeholder="SSH host (user@host, optional)", id="hb-ssh-host")
            yield Input(placeholder="SSH port (default: 22)", id="hb-ssh-port")
            yield Input(placeholder="SSH key path (optional)", id="hb-ssh-key")
            yield Input(placeholder="SSH password (optional)", id="hb-ssh-password", password=True)
            yield Checkbox("SSH sudo", id="hb-ssh-sudo", value=True)
            yield Checkbox("No docker install", id="hb-no-docker-install")
            yield Checkbox("Force recreate containers", id="hb-force")
            yield Checkbox("Rotate JWT secret", id="hb-rotate-jwt")
            yield Checkbox("Wipe data", id="hb-wipe-data")
            yield Checkbox("Assume yes", id="hb-assume-yes", value=True)
            with Horizontal():
                yield Button("Cancel", id="hb-cancel")
                yield Button("Run bootstrap", id="hb-run")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hb-cancel":
            self.dismiss(None)
            return
        data = self._collect()
        if data is None:
            return
        self.dismiss(data)

    def _collect(self) -> dict | None:
        def _val(id_: str) -> str:
            return (self.query_one(f"#{id_}", Input).value or "").strip()

        def _bool(id_: str) -> bool:
            return bool(self.query_one(f"#{id_}", Checkbox).value)

        api_url = _val("hb-api-url")
        if not api_url:
            self.app._set_status("API URL is required.")
            return None
        admin_user = _val("hb-admin-username")
        admin_pass = _val("hb-admin-password")
        x_root = _val("hb-x-root-secret")
        db_pass = _val("hb-db-password")
        if not (admin_user and admin_pass and x_root and db_pass):
            self.app._set_status("Admin/db/root secrets are required.")
            return None

        no_license = _bool("hb-no-license")
        license_key = _val("hb-license-key")
        if not no_license and not license_key:
            self.app._set_status("License key is required (or enable No license).")
            return None

        ssh_host = _val("hb-ssh-host") or None
        ssh_key = _val("hb-ssh-key") or None
        ssh_password = _val("hb-ssh-password") or None
        if ssh_host and not (ssh_key or ssh_password):
            self.app._set_status("SSH key or password is required for SSH bootstrap.")
            return None
        if ssh_password and is_windows():
            self.app._set_status("SSH password auth is not supported on Windows. Use SSH key.")
            return None

        data = dict(
            api_url=api_url,
            host_name=_val("hb-host-name") or None,
            x_root_secret=x_root,
            db_password=db_pass,
            admin_username=admin_user,
            admin_password=admin_pass,
            admin_api_key_name=_val("hb-admin-api-key") or "root",
            telegram_bot_token=_val("hb-telegram-token") or None,
            install_dir=_val("hb-install-dir") or DEFAULT_INSTALL_DIR,
            registry=_val("hb-registry") or DEFAULT_REGISTRY,
            tag=_val("hb-tag") or DEFAULT_TAG,
            version=_val("hb-version") or None,
            lic_url=_val("hb-lic-url") or DEFAULT_LIC_URL,
            no_license=no_license,
            license_key=license_key or None,
            force_registry_password=_bool("hb-force-registry-password"),
            skip_https=_bool("hb-skip-https"),
            non_interactive=True,
            assume_yes=_bool("hb-assume-yes"),
            no_docker_install=_bool("hb-no-docker-install"),
            force=_bool("hb-force"),
            rotate_jwt_secret=_bool("hb-rotate-jwt"),
            wipe_data=_bool("hb-wipe-data"),
            confirm_wipe=True,
            ssh_host=ssh_host,
            ssh_port=int(_val("hb-ssh-port") or 22),
            ssh_key=ssh_key,
            ssh_password=ssh_password,
            ssh_sudo=_bool("hb-ssh-sudo"),
            https_after=_bool("hb-https-after"),
            https_domain=_val("hb-https-domain") or None,
            https_email=_val("hb-https-email") or None,
            https_http01=_bool("hb-https-http01"),
            https_api_port=int(_val("hb-https-api-port") or 8010),
        )
        if data["https_after"]:
            try:
                normalize_domain(data["https_domain"] or "")
            except Exception:
                self.app._set_status("HTTPS domain is invalid.")
                return None
            if "@" not in (data["https_email"] or ""):
                self.app._set_status("HTTPS email is invalid.")
                return None
        return data


class HostHttpsScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("HTTPS setup")
            yield Input(placeholder="Domain (api.example.com)", id="hh-domain")
            yield Input(placeholder="Email (admin@example.com)", id="hh-email")
            yield Input(placeholder="API port (default: 8010)", id="hh-api-port")
            yield Checkbox("HTTP-01 challenge", id="hh-http01", value=True)
            yield Input(placeholder="SSH host (optional)", id="hh-ssh-host")
            yield Input(placeholder="SSH port (default: 22)", id="hh-ssh-port")
            yield Input(placeholder="SSH key (optional)", id="hh-ssh-key")
            yield Input(placeholder="SSH password (optional)", id="hh-ssh-password", password=True)
            yield Checkbox("SSH sudo", id="hh-ssh-sudo", value=True)
            with Horizontal():
                yield Button("Cancel", id="hh-cancel")
                yield Button("Run", id="hh-run")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hh-cancel":
            self.dismiss(None)
            return
        domain = (self.query_one("#hh-domain", Input).value or "").strip()
        email = (self.query_one("#hh-email", Input).value or "").strip()
        if not domain or "@" not in email:
            self.app._set_status("Domain and valid email are required.")
            return
        ssh_host = (self.query_one("#hh-ssh-host", Input).value or "").strip() or None
        ssh_key = (self.query_one("#hh-ssh-key", Input).value or "").strip() or None
        ssh_password = (self.query_one("#hh-ssh-password", Input).value or "").strip() or None
        if ssh_host and not (ssh_key or ssh_password):
            self.app._set_status("SSH key or password is required.")
            return
        if ssh_password and is_windows():
            self.app._set_status("SSH password auth is not supported on Windows. Use SSH key.")
            return
        data = dict(
            domain=domain,
            email=email,
            api_port=int((self.query_one("#hh-api-port", Input).value or "8010").strip() or 8010),
            http01=bool(self.query_one("#hh-http01", Checkbox).value),
            ssh_host=ssh_host,
            ssh_port=int((self.query_one("#hh-ssh-port", Input).value or "22").strip() or 22),
            ssh_key=ssh_key,
            ssh_password=ssh_password,
            ssh_sudo=bool(self.query_one("#hh-ssh-sudo", Checkbox).value),
        )
        self.dismiss(data)


class HostPurgeScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("Host purge")
            yield Input(placeholder="License API URL (optional)", id="hp-lic-url")
            yield Input(placeholder="License ID", id="hp-license-id")
            yield Input(placeholder="Type DELETE to confirm", id="hp-confirm")
            with Horizontal():
                yield Button("Cancel", id="hp-cancel")
                yield Button("Run purge", id="hp-run")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hp-cancel":
            self.dismiss(None)
            return
        confirm = (self.query_one("#hp-confirm", Input).value or "").strip()
        if confirm != "DELETE":
            self.app._set_status("Confirmation failed. Type DELETE.")
            return
        license_id = (self.query_one("#hp-license-id", Input).value or "").strip()
        if not license_id:
            self.app._set_status("License id is required.")
            return
        self.dismiss(
            {
                "lic_url": (self.query_one("#hp-lic-url", Input).value or "").strip() or None,
                "license_id": license_id,
            }
        )


class AuthLoginScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("Auth login")
            yield Input(placeholder="Username", id="al-username")
            yield Input(placeholder="Password", id="al-password", password=True)
            yield Input(placeholder="Base URL override (optional)", id="al-base-url")
            with Horizontal():
                yield Button("Cancel", id="al-cancel")
                yield Button("Login", id="al-login")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "al-cancel":
            self.dismiss(None)
            return
        username = (self.query_one("#al-username", Input).value or "").strip()
        password = (self.query_one("#al-password", Input).value or "").strip()
        base_url = (self.query_one("#al-base-url", Input).value or "").strip() or None
        if not username or not password:
            self.app._set_status("Username and password are required.")
            return
        self.dismiss({"username": username, "password": password, "base_url": base_url})


class AuthApiKeyScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("Auth login (API key)")
            yield Input(placeholder="API key", id="ak-key", password=True)
            yield Input(placeholder="Base URL override (optional)", id="ak-base-url")
            with Horizontal():
                yield Button("Cancel", id="ak-cancel")
                yield Button("Login", id="ak-login")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ak-cancel":
            self.dismiss(None)
            return
        api_key = (self.query_one("#ak-key", Input).value or "").strip()
        base_url = (self.query_one("#ak-base-url", Input).value or "").strip() or None
        if not api_key:
            self.app._set_status("API key is required.")
            return
        self.dismiss({"api_key": api_key, "base_url": base_url})


class AuthLogoutScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("Logout")
            yield Checkbox("Also logout from Docker registry", id="ao-docker", value=True)
            with Horizontal():
                yield Button("Cancel", id="ao-cancel")
                yield Button("Logout", id="ao-logout")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ao-cancel":
            self.dismiss(None)
            return
        docker = bool(self.query_one("#ao-docker", Checkbox).value)
        self.dismiss({"docker": docker})


class PortalAuthScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal"):
            yield Static("Portal auth")
            yield Input(placeholder="License API URL (optional)", id="pa-lic-url")
            yield Checkbox("I already have an account (login)", id="pa-has-account", value=True)
            yield Input(placeholder="Login (email or username)", id="pa-login")
            yield Input(placeholder="Password", id="pa-password", password=True)
            yield Input(placeholder="2FA OTP (if enabled)", id="pa-otp-2fa")
            yield Static("Register (if no account)")
            yield Input(placeholder="Email", id="pa-email")
            yield Input(placeholder="Username", id="pa-username")
            yield Input(placeholder="Password", id="pa-password-reg", password=True)
            yield Input(placeholder="Confirm password", id="pa-password-confirm", password=True)
            yield Input(placeholder="Email verification code", id="pa-otp-email")
            with Horizontal():
                yield Button("Cancel", id="pa-cancel")
                yield Button("Submit", id="pa-submit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pa-cancel":
            self.dismiss(None)
            return
        data = {
            "lic_url": (self.query_one("#pa-lic-url", Input).value or "").strip() or None,
            "has_account": bool(self.query_one("#pa-has-account", Checkbox).value),
            "login": (self.query_one("#pa-login", Input).value or "").strip(),
            "password": (self.query_one("#pa-password", Input).value or "").strip(),
            "otp_2fa": (self.query_one("#pa-otp-2fa", Input).value or "").strip() or None,
            "email": (self.query_one("#pa-email", Input).value or "").strip(),
            "username": (self.query_one("#pa-username", Input).value or "").strip(),
            "password_reg": (self.query_one("#pa-password-reg", Input).value or "").strip(),
            "password_confirm": (self.query_one("#pa-password-confirm", Input).value or "").strip(),
            "otp_email": (self.query_one("#pa-otp-email", Input).value or "").strip(),
        }
        self.dismiss(data)


class PortalTelemetryScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("Portal telemetry")
            yield Input(placeholder="License API URL (optional)", id="pt-lic-url")
            yield Checkbox("Enable telemetry", id="pt-enabled", value=True)
            with Horizontal():
                yield Button("Cancel", id="pt-cancel")
                yield Button("Apply", id="pt-apply")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pt-cancel":
            self.dismiss(None)
            return
        self.dismiss(
            {
                "lic_url": (self.query_one("#pt-lic-url", Input).value or "").strip() or None,
                "enabled": bool(self.query_one("#pt-enabled", Checkbox).value),
            }
        )


class AgentInstallScreen(ModalScreen[dict]):
    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal"):
            yield Static("Agent install")
            yield Input(placeholder="Invite token", id="ai-invite")
            yield Input(placeholder="SSH target (user@host)", id="ai-ssh")
            yield Input(placeholder="SSH port (default 22)", id="ai-port")
            yield Input(placeholder="SSH key path", id="ai-key")
            yield Input(placeholder="SSH password (optional)", id="ai-password", password=True)
            yield Checkbox("Use sudo", id="ai-sudo")
            yield Input(placeholder="Sudo password (optional)", id="ai-sudo-password", password=True)
            yield Checkbox("Install docker if missing", id="ai-with-docker")
            yield Checkbox("Dry run", id="ai-dry-run")
            yield Input(placeholder="API URL override (optional)", id="ai-api-url")
            yield Checkbox("Force re-register", id="ai-force-reregister")
            yield Input(placeholder="Timeout (default 60)", id="ai-timeout")
            yield Checkbox("No wait", id="ai-no-wait")
            yield Checkbox("Show agent after registration", id="ai-show")
            yield Checkbox("Watch agent status", id="ai-watch")
            yield Checkbox("Follow agent logs", id="ai-follow")
            yield Checkbox("Local install", id="ai-local")
            yield Input(placeholder="Local path (optional)", id="ai-local-path")
            yield Checkbox("Create server after registration", id="ai-create-server")
            yield Input(placeholder="Version tag (optional)", id="ai-version")
            yield Input(placeholder="License API URL (optional)", id="ai-lic-url")
            yield Checkbox("No license", id="ai-no-license")
            yield Input(placeholder="Image tag fallback (default 1.0.0)", id="ai-tag")
            with Horizontal():
                yield Button("Cancel", id="ai-cancel")
                yield Button("Install", id="ai-install")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ai-cancel":
            self.dismiss(None)
            return
        invite = (self.query_one("#ai-invite", Input).value or "").strip()
        if not invite:
            self.app._set_status("Invite token is required.")
            return
        ssh_password = (self.query_one("#ai-password", Input).value or "").strip() or None
        if ssh_password and is_windows():
            self.app._set_status("SSH password auth is not supported on Windows. Use SSH key.")
            return
        sudo_password = (self.query_one("#ai-sudo-password", Input).value or "").strip() or None
        data = {
            "invite": invite,
            "ssh_target": (self.query_one("#ai-ssh", Input).value or "").strip() or None,
            "port": int((self.query_one("#ai-port", Input).value or "22").strip() or 22),
            "key": (self.query_one("#ai-key", Input).value or "").strip() or None,
            "password": bool(ssh_password),
            "ssh_password": ssh_password,
            "sudo": bool(self.query_one("#ai-sudo", Checkbox).value),
            "sudo_password": bool(sudo_password),
            "sudo_password_value": sudo_password,
            "with_docker": bool(self.query_one("#ai-with-docker", Checkbox).value),
            "dry_run": bool(self.query_one("#ai-dry-run", Checkbox).value),
            "api_url": (self.query_one("#ai-api-url", Input).value or "").strip() or None,
            "force_reregister": bool(self.query_one("#ai-force-reregister", Checkbox).value),
            "timeout": int((self.query_one("#ai-timeout", Input).value or "60").strip() or 60),
            "no_wait": bool(self.query_one("#ai-no-wait", Checkbox).value),
            "show": bool(self.query_one("#ai-show", Checkbox).value),
            "json_out": False,
            "watch": bool(self.query_one("#ai-watch", Checkbox).value),
            "follow": bool(self.query_one("#ai-follow", Checkbox).value),
            "local": bool(self.query_one("#ai-local", Checkbox).value),
            "local_path": (self.query_one("#ai-local-path", Input).value or "").strip() or None,
            "create_server": bool(self.query_one("#ai-create-server", Checkbox).value),
            "version": (self.query_one("#ai-version", Input).value or "").strip() or None,
            "lic_url": (self.query_one("#ai-lic-url", Input).value or "").strip() or DEFAULT_LIC_URL,
            "no_license": bool(self.query_one("#ai-no-license", Checkbox).value),
            "tag": (self.query_one("#ai-tag", Input).value or "").strip() or DEFAULT_TAG,
        }
        self.dismiss(data)


class WizardScreen(ModalScreen[dict]):
    def __init__(self, *, title: str, steps: list[dict[str, Any]]) -> None:
        super().__init__()
        self._title = title
        self._steps = steps
        self._values: dict[str, Any] = {}
        self._pos = 0

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static(self._title, id="wiz-title")
            yield Static("", id="wiz-step")
            yield Static("", id="wiz-label")
            yield Input(id="wiz-input")
            yield Input(id="wiz-password", password=True, classes="hidden")
            yield Checkbox("", id="wiz-bool", classes="hidden")
            with Horizontal():
                yield Button("Back", id="wiz-back")
                yield Button("Next", id="wiz-next")
                yield Button("Finish", id="wiz-finish")
                yield Button("Cancel", id="wiz-cancel")

    def on_mount(self) -> None:
        self._pos = 0
        self._show_step()

    def _visible_indices(self) -> list[int]:
        result = []
        for idx, step in enumerate(self._steps):
            cond = step.get("when")
            if cond is None:
                result.append(idx)
                continue
            try:
                if bool(cond(self._values)):
                    result.append(idx)
            except Exception:
                continue
        return result

    def _current_step(self) -> tuple[int, dict[str, Any]] | None:
        visible = self._visible_indices()
        if not visible:
            return None
        if self._pos < 0:
            self._pos = 0
        if self._pos >= len(visible):
            self._pos = len(visible) - 1
        idx = visible[self._pos]
        return idx, self._steps[idx]

    def _show_step(self) -> None:
        current = self._current_step()
        if not current:
            return
        _, step = current
        label = step.get("label") or step.get("key") or ""
        kind = step.get("kind", "text")
        visible = self._visible_indices()
        self.query_one("#wiz-step", Static).update(f"Step {self._pos + 1} of {len(visible)}")
        self.query_one("#wiz-label", Static).update(label)
        input_widget = self.query_one("#wiz-input", Input)
        pass_widget = self.query_one("#wiz-password", Input)
        bool_widget = self.query_one("#wiz-bool", Checkbox)

        input_widget.remove_class("hidden")
        pass_widget.add_class("hidden")
        bool_widget.add_class("hidden")

        value = self._values.get(step.get("key"))
        if value is None:
            value = step.get("default")

        if kind == "password":
            input_widget.add_class("hidden")
            pass_widget.remove_class("hidden")
            pass_widget.value = "" if value is None else str(value)
        elif kind == "bool":
            input_widget.add_class("hidden")
            bool_widget.remove_class("hidden")
            bool_widget.label = label
            bool_widget.value = bool(value) if value is not None else bool(step.get("default", False))
        else:
            input_widget.value = "" if value is None else str(value)

    def _read_value(self, step: dict[str, Any]) -> tuple[bool, Any]:
        key = step.get("key")
        kind = step.get("kind", "text")
        required = bool(step.get("required"))
        if kind == "bool":
            value = bool(self.query_one("#wiz-bool", Checkbox).value)
        elif kind == "password":
            value = (self.query_one("#wiz-password", Input).value or "").strip()
        else:
            value = (self.query_one("#wiz-input", Input).value or "").strip()
        if required and not value:
            self.app._set_status(f"{key or 'Field'} is required.")
            return False, None
        if kind == "int":
            if not value:
                return True, None
            try:
                return True, int(value)
            except ValueError:
                self.app._set_status(f"{key or 'Field'} must be an integer.")
                return False, None
        return True, value

    def _validate_step(self, step: dict[str, Any], value: Any) -> bool:
        return True

    def _save_current(self) -> bool:
        current = self._current_step()
        if not current:
            return True
        _, step = current
        ok, value = self._read_value(step)
        if not ok:
            return False
        if not self._validate_step(step, value):
            return False
        key = step.get("key")
        if key:
            self._values[key] = value
        return True

    def _build_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for step in self._steps:
            key = step.get("key")
            if not key:
                continue
            value = self._values.get(key)
            if value is None and "default" in step:
                value = step.get("default")
            payload[key] = value
        return payload

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "wiz-cancel":
            self.dismiss(None)
            return
        if event.button.id == "wiz-back":
            if self._pos > 0:
                self._pos -= 1
                self._show_step()
            return
        if event.button.id == "wiz-next":
            if not self._save_current():
                return
            visible = self._visible_indices()
            if self._pos < len(visible) - 1:
                self._pos += 1
                self._show_step()
            else:
                self.dismiss(self._build_payload())
            return
        if event.button.id == "wiz-finish":
            if not self._save_current():
                return
            self.dismiss(self._build_payload())


class HostBootstrapWizardScreen(WizardScreen):
    def __init__(self) -> None:
        steps = [
            {"key": "install_via_ssh", "label": "Install via SSH", "kind": "bool", "default": False},
            {
                "key": "ssh_host",
                "label": "SSH host (user@host)",
                "kind": "text",
                "required": True,
                "when": lambda v: bool(v.get("install_via_ssh")),
            },
            {"key": "ssh_port", "label": "SSH port", "kind": "int", "default": 22,
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "ssh_key", "label": "SSH key path (optional)", "kind": "text",
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "ssh_password", "label": "SSH password (optional)", "kind": "password",
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "ssh_sudo", "label": "SSH sudo", "kind": "bool", "default": True,
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "license_key", "label": "License key", "kind": "password", "required": True},
            {"key": "api_url", "label": "API URL", "kind": "text", "required": True},
            {"key": "host_name", "label": "Host name (optional)", "kind": "text"},
            {"key": "x_root_secret", "label": "X-Root-Secret", "kind": "password", "required": True},
            {"key": "db_password", "label": "DB password", "kind": "password", "required": True},
            {"key": "admin_username", "label": "Admin username", "kind": "text", "required": True},
            {"key": "admin_password", "label": "Admin password", "kind": "password", "required": True},
            {"key": "admin_api_key_name", "label": "Admin API key name", "kind": "text", "default": "root"},
            {"key": "install_dir", "label": "Install dir", "kind": "text", "default": DEFAULT_INSTALL_DIR},
            {"key": "tag", "label": "Host tag (from license)", "kind": "text", "default": DEFAULT_TAG},
            {"key": "force_registry_password", "label": "Force registry password rotation", "kind": "bool",
             "default": True},
            {"key": "no_docker_install", "label": "No docker install", "kind": "bool", "default": False},
            {"key": "force", "label": "Force recreate containers", "kind": "bool", "default": False},
            {"key": "rotate_jwt_secret", "label": "Rotate JWT secret", "kind": "bool", "default": False},
            {"key": "wipe_data", "label": "Wipe data", "kind": "bool", "default": False},
            {"key": "assume_yes", "label": "Assume yes", "kind": "bool", "default": True},
            {"key": "https_after", "label": "Setup HTTPS after bootstrap", "kind": "bool", "default": False},
            {
                "key": "https_domain",
                "label": "HTTPS domain",
                "kind": "text",
                "required": True,
                "when": lambda v: bool(v.get("https_after")),
            },
            {
                "key": "https_email",
                "label": "HTTPS email",
                "kind": "text",
                "required": True,
                "when": lambda v: bool(v.get("https_after")),
            },
            {"key": "https_http01", "label": "HTTPS HTTP-01 challenge", "kind": "bool", "default": True,
             "when": lambda v: bool(v.get("https_after"))},
            {"key": "https_api_port", "label": "HTTPS API port", "kind": "int", "default": 8010,
             "when": lambda v: bool(v.get("https_after"))},
        ]
        super().__init__(title="Host bootstrap wizard", steps=steps)

    def _validate_step(self, step: dict[str, Any], value: Any) -> bool:
        if step.get("key") == "install_via_ssh" and value is False and is_windows():
            self.app._set_status("Local host bootstrap is not supported on Windows. Use SSH.")
            return False
        if step.get("key") == "ssh_password" and value and is_windows():
            self.app._set_status("SSH password auth is not supported on Windows. Use SSH key.")
            return False
        if step.get("key") == "license_key":
            lic_key = str(value or "").strip()
            if not lic_key:
                self.app._set_status("License key is required.")
                return False
            try:
                entitlements = resolve_entitlements(SaharoTUI.LIC_URL_FIXED, lic_key)
            except LicenseEntitlementsError as exc:
                self.app._set_status(str(exc))
                return False
            resolved_tag = getattr(entitlements, "host", None)
            if resolved_tag:
                self._values["tag"] = resolved_tag
                self.app._set_status(f"Resolved host tag: {resolved_tag}")
        return True

    def _build_payload(self) -> dict[str, Any]:
        payload = super()._build_payload()
        install_via_ssh = bool(payload.pop("install_via_ssh", False))
        if not install_via_ssh:
            payload["ssh_host"] = None
        for key in (
            "host_name",
            "license_key",
            "ssh_host",
            "ssh_key",
            "ssh_password",
        ):
            if payload.get(key) == "":
                payload[key] = None
        payload["telegram_bot_token"] = None
        payload["version"] = None
        payload["lic_url"] = SaharoTUI.LIC_URL_FIXED
        payload["no_license"] = False
        payload["registry"] = DEFAULT_REGISTRY
        payload["skip_https"] = not bool(payload.get("https_after", False))
        payload["non_interactive"] = True
        payload["confirm_wipe"] = True
        payload["assume_yes"] = bool(payload.get("assume_yes", True))
        payload["https_after"] = bool(payload.get("https_after", False))
        return payload


class ServerBootstrapWizardScreen(WizardScreen):
    def __init__(self) -> None:
        steps = [
            {"key": "install_via_ssh", "label": "Install via SSH", "kind": "bool", "default": False},
            {"key": "ssh_target", "label": "SSH target (user@host)", "kind": "text",
             "required": True, "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "port", "label": "SSH port", "kind": "int", "default": 22,
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "key", "label": "SSH key path (optional)", "kind": "text",
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "ssh_password", "label": "SSH password (optional)", "kind": "password",
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "sudo", "label": "Use sudo", "kind": "bool", "default": True,
             "when": lambda v: bool(v.get("install_via_ssh"))},
            {"key": "sudo_password_value", "label": "Sudo password (optional)", "kind": "password",
             "when": lambda v: bool(v.get("install_via_ssh")) and v.get("sudo")},
            {"key": "local_path", "label": "Local path (optional)", "kind": "text",
             "when": lambda v: not v.get("install_via_ssh")},
            {"key": "name", "label": "Server name", "kind": "text", "required": True},
            {"key": "host", "label": "Server host (IP or DNS)", "kind": "text", "required": True},
            {"key": "note", "label": "Note (optional)", "kind": "text"},
            {"key": "invite_expires_minutes", "label": "Invite expires minutes (optional)", "kind": "int"},
            {"key": "no_remote_login", "label": "Skip docker login on remote host", "kind": "bool",
             "default": False},
            {"key": "with_docker", "label": "Install docker if missing", "kind": "bool", "default": False},
            {"key": "dry_run", "label": "Dry run", "kind": "bool", "default": False},
            {"key": "api_url", "label": "API URL override (optional)", "kind": "text"},
            {"key": "force_reregister", "label": "Force re-register", "kind": "bool", "default": False},
            {"key": "agent_interval_s", "label": "Agent loop interval (seconds)", "kind": "int",
             "default": DEFAULT_AGENT_LOOP_INTERVAL_S},
            {"key": "register_timeout", "label": "Register timeout (seconds)", "kind": "int", "default": 60},
            {"key": "wait", "label": "Wait for completion", "kind": "bool", "default": True},
            {"key": "wait_timeout", "label": "Wait timeout (seconds)", "kind": "int", "default": 300,
             "when": lambda v: bool(v.get("wait"))},
            {"key": "wait_interval", "label": "Wait interval (seconds)", "kind": "int", "default": 5,
             "when": lambda v: bool(v.get("wait"))},
            {"key": "license_key", "label": "License key (optional)", "kind": "password"},
            {"key": "agent_version", "label": "Agent version (from license, optional)", "kind": "text"},
        ]
        super().__init__(title="Server bootstrap wizard", steps=steps)

    def _validate_step(self, step: dict[str, Any], value: Any) -> bool:
        if step.get("key") == "install_via_ssh" and value is False and is_windows():
            self.app._set_status("Local server bootstrap is not supported on Windows.")
            return False
        if step.get("key") == "ssh_password" and value and is_windows():
            self.app._set_status("SSH password auth is not supported on Windows. Use SSH key.")
            return False
        if step.get("key") == "license_key" and value:
            lic_key = str(value or "").strip()
            try:
                entitlements = resolve_entitlements(SaharoTUI.LIC_URL_FIXED, lic_key)
            except LicenseEntitlementsError as exc:
                self.app._set_status(str(exc))
                return False
            resolved_tag = getattr(entitlements, "agent", None)
            if resolved_tag:
                self._values["agent_version"] = resolved_tag
                self.app._set_status(f"Resolved agent version: {resolved_tag}")
        return True

    def _build_payload(self) -> dict[str, Any]:
        payload = super()._build_payload()
        install_via_ssh = bool(payload.pop("install_via_ssh", False))
        payload["local"] = not install_via_ssh
        for key in (
            "note",
            "local_path",
            "api_url",
            "license_key",
            "agent_version",
            "key",
            "ssh_password",
        ):
            if payload.get(key) == "":
                payload[key] = None
        payload["password"] = False
        payload["sudo_password"] = False
        payload["wait"] = bool(payload.get("wait", True))
        payload["json_out"] = False
        payload["base_url"] = None
        payload["lic_url"] = SaharoTUI.LIC_URL_FIXED
        payload["no_license"] = False
        payload["registry"] = DEFAULT_REGISTRY
        if payload.get("local"):
            payload["ssh_target"] = None
        return payload
def run_tui() -> None:
    SaharoTUI().run()
