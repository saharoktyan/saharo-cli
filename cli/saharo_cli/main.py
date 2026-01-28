from __future__ import annotations

import sys

import typer

from .auth_state import resolve_auth_context
from .commands import auth_cmd, config_cmd, invite_cmd, settings_cmd, health_cmd, self_cmd, updates_cmd, portal_cmd
from .commands.grants_cmd import app as grants_app
from .commands.health_cmd import app as health_app
from .commands.host_cmd import app as host_app
from .commands.jobs_cmd import app as jobs_app
from .commands.logs_cmd import app as logs_app
from .commands.servers_cmd import app as servers_app
from .commands.users_cmd import app as users_app
from .logging_ import setup_logging


def _build_app() -> typer.Typer:
    app = typer.Typer(
        name="saharo",
        help="saharo CLI",
        no_args_is_help=False,
    )

    ctx = resolve_auth_context(check_remote=False)

    # Always available
    app.add_typer(settings_cmd.app, name="settings")
    app.add_typer(host_app, name="host")
    app.add_typer(self_cmd.app, name="self")
    app.add_typer(updates_cmd.app, name="updates")
    app.command("health")(health_cmd.health)
    app.add_typer(invite_cmd.app_user, name="invite", hidden=True)

    if ctx.state in {"no_base_url", "no_token", "invalid_token"}:
        # Limited mode: allow login + settings.
        app.add_typer(auth_cmd.app, name="auth")
        # config get is useful even before admin privileges (for end-users)
        app.add_typer(config_cmd.app, name="config")
    else:
        # Authenticated
        app.add_typer(auth_cmd.app, name="auth")
        app.command("whoami")(auth_cmd.whoami_impl)
        app.add_typer(config_cmd.app, name="config")

        # Health is available to all authenticated users
        app.add_typer(health_app, name="")

        # Admin-only apps (also allow when auth cannot be verified yet)
        if ctx.role == "admin" or ctx.state in {"token_present", "token_unverified"}:
            app.add_typer(servers_app, name="servers")
            app.add_typer(jobs_app, name="jobs")
            app.add_typer(users_app, name="users")
            app.add_typer(grants_app, name="grants")
            app.add_typer(logs_app, name="logs")
            app.add_typer(portal_cmd.app, name="portal")
            app.command("invite-admin", hidden=True)(invite_cmd.create_invite)

    @app.callback(invoke_without_command=True)
    def _main(
            ctx: typer.Context,
            verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose logs."),
    ):
        setup_logging(verbose)
        if ctx.invoked_subcommand is None and len(sys.argv) == 1:
            from .interactive_menu import run_interactive_menu

            tokens = run_interactive_menu(app)
            if not tokens:
                raise typer.Exit(code=0)
            command = typer.main.get_command(app)
            command.main(
                args=tokens,
                prog_name=ctx.info_name or sys.argv[0],
                standalone_mode=True,
            )
            raise typer.Exit(code=0)

    return app


app = _build_app()
