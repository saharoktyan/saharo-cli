"""
Services CLI commands.

Commands for managing custom service definitions.
"""
import typer
import yaml as pyyaml
from pathlib import Path
from rich.table import Table
from saharo_client import ApiError

from .. import console
from ..config import load_config
from ..http import make_client
from ..interactive import confirm_choice, select_custom_service
from ..formatting import format_list_timestamp

app = typer.Typer(help="Manage custom service definitions.")


@app.command("add")
def add_service(
    yaml_file: Path = typer.Argument(..., exists=True, help="YAML definition file."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    """
    Add a custom service from a YAML definition file.
    """
    # Read YAML file
    try:
        yaml_content = yaml_file.read_text(encoding="utf-8")
    except Exception as e:
        console.err(f"Failed to read file: {e}")
        raise typer.Exit(code=2)
    
    # Parse YAML to extract service code and display name
    try:
        data = pyyaml.safe_load(yaml_content)
        code = (data.get("name") or "").strip()
        display_name = (data.get("display_name") or code).strip()
        
        if not code:
            console.err("YAML file must contain a 'name' field.")
            raise typer.Exit(code=2)
    except Exception as e:
        console.err(f"Invalid YAML: {e}")
        raise typer.Exit(code=2)
    
    # Create service via API
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    
    try:
        service = client.admin_custom_service_create(
            code=code,
            display_name=display_name,
            yaml_definition=yaml_content,
        )
        console.ok(f"✓ Service '{code}' added successfully (ID: {service['id']})")
        console.info(f"  Display name: {display_name}")
        console.info(f"  Enabled: {service['enabled']}")
    except ApiError as e:
        if e.status_code == 409:
            console.err(f"Service '{code}' already exists.")
        elif e.status_code == 400:
            console.err(f"Validation failed: {e.body.get('detail', 'Invalid YAML definition') if isinstance(e.body, dict) else str(e)}")
        else:
            console.err(f"Failed to add service: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("list")
def list_services(
    enabled_only: bool = typer.Option(False, "--enabled-only", help="Show only enabled services."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
    json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """
    List all custom service definitions.
    """
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    
    try:
        services = client.admin_custom_services_list(enabled_only=enabled_only)
        
        if json_out:
            console.print_json(services)
            return

        if not services:
            console.info("No custom services found.")
            return
        
        table = Table(title="Custom Services")
        table.add_column("id", style="bold")
        table.add_column("code")
        table.add_column("display name")
        table.add_column("status")
        table.add_column("created", no_wrap=True)
        
        for svc in services:
            status = "[green]Enabled[/]" if svc["enabled"] else "[red]Disabled[/]"
            table.add_row(
                str(svc["id"]),
                svc["code"],
                svc["display_name"],
                status,
                format_list_timestamp(svc["created_at"]),
            )
        
        console.console.print(table)
    except ApiError as e:
        console.err(f"Failed to list services: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("get")
def get_service(
    code_or_id: str | None = typer.Argument(None, help="Service code or ID."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
    json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """
    Show details of a custom service.
    """
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    
    try:
        if code_or_id is None:
            service_id = select_custom_service(client)
            service = client.admin_custom_service_get(service_id)
        elif code_or_id.isdigit():
            service = client.admin_custom_service_get(int(code_or_id))
        else:
            service = client.admin_custom_service_get_by_code(code_or_id)
        
        if json_out:
            console.print_json(service)
            return

        console.rule(f"Service: {service['display_name']}")
        console.info(f"ID: {service['id']}")
        console.info(f"Code: {service['code']}")
        console.info(f"Status: {'[green]Enabled[/]' if service['enabled'] else '[red]Disabled[/]'}")
        console.info(f"Created: {service['created_at']}")
        console.info(f"Updated: {service['updated_at']}")
        console.console.print("\n[bold]YAML Definition:[/bold]")
        console.console.print(f"[dim]{service['yaml_definition']}[/dim]\n")
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Service '{code_or_id}' not found.")
        else:
            console.err(f"Failed to get service: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("delete")
def delete_service(
    code_or_id: str | None = typer.Argument(None, help="Service code or ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    """
    Remove a custom service definition.
    """
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    
    try:
        # Get service first to confirm
        if code_or_id is None:
            service_id = select_custom_service(client)
            service = client.admin_custom_service_get(service_id)
        elif code_or_id.isdigit():
            service = client.admin_custom_service_get(int(code_or_id))
        else:
            service = client.admin_custom_service_get_by_code(code_or_id)
        
        service_id = service["id"]
        code = service["code"]
        
        # Confirm deletion
        if not force:
            if not confirm_choice(f"Remove service '{code}' ({service['display_name']})?", default=False):
                console.info("Aborted.")
                return
        
        client.admin_custom_service_delete(service_id)
        console.ok(f"✓ Service '{code}' removed.")
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Service '{code_or_id}' not found.")
        else:
            console.err(f"Failed to remove service: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("remove", hidden=True)
def remove_service(
    code_or_id: str | None = typer.Argument(None, help="Service code or ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    delete_service(code_or_id=code_or_id, force=force, base_url=base_url)


@app.command("validate")
def validate_service(
    yaml_file: Path = typer.Argument(..., exists=True, help="YAML definition file."),
):
    """
    Validate a YAML service definition file without adding it.
    """
    # Read YAML file
    try:
        yaml_content = yaml_file.read_text(encoding="utf-8")
    except Exception as e:
        console.err(f"Failed to read file: {e}")
        raise typer.Exit(code=2)
    
    # Import parser from agent code (local validation)
    try:
        import sys
        import os
        
        # Add agent path to sys.path
        # We need to reach saharo-host-monorepo/http-agent
        # Current file is in saharo-cli/cli/saharo_cli/commands/services_cmd.py
        # Target is ../../../../../saharo-host-monorepo/http-agent
        script_dir = os.path.dirname(os.path.abspath(__file__))
        agent_path = os.path.normpath(os.path.join(script_dir, "../../../../saharo-host-monorepo/http-agent"))
        
        if os.path.exists(agent_path) and agent_path not in sys.path:
            sys.path.insert(0, agent_path)
        
        from agent.services.yaml_parser import parse_service_yaml
        
        definition = parse_service_yaml(yaml_content)
        
        console.ok("✓ YAML is valid")
        console.info(f"  Service name: {definition.name}")
        console.info(f"  Display name: {definition.display_name}")
        console.info(f"  Container image: {definition.container.image}")
        
    except ImportError:
        console.warn("Could not find agent.services.yaml_parser for local validation.")
        console.info("Falling back to basic YAML check...")
        try:
            data = pyyaml.safe_load(yaml_content)
            if not data.get("name"):
                raise ValueError("Missing 'name' field")
            console.ok("✓ Basic YAML structure is valid.")
        except Exception as e:
            console.err(f"✗ Validation failed: {e}")
            raise typer.Exit(code=2)
    except Exception as e:
        console.err(f"✗ Validation failed: {e}")
        raise typer.Exit(code=2)
