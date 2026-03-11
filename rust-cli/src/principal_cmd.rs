use std::io;
use std::io::IsTerminal;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use dialoguer::{theme::ColorfulTheme, Select};
use saharo_sdk::{AdminFacade, ApiClient, ApiError};
use serde_json::{json, Value};

use crate::config::{load_config, normalize_base_url};
use crate::{
    DeleteGrantArgs, GetGrantArgs, GetGrantsArgs, GetUserArgs, GetUsersArgs, SetUserRoleArgs,
};

pub fn get_users(args: GetUsersArgs) -> io::Result<i32> {
    if args.page < 1 || args.page_size < 1 {
        crate::console::err("--page and --page-size must be >= 1.");
        return Ok(2);
    }
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let offset = (args.page - 1) * args.page_size;
    let data = match admin.list_users_raw(args.q.as_deref(), Some(args.page_size), Some(offset)) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list users"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "username", "role", "telegram_id"]);
    for u in items {
        table.add_row(vec![
            value_text(u.get("id")),
            value_text(u.get("username")),
            value_text(u.get("role")),
            value_text(u.get("telegram_id")),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_user(args: GetUserArgs, describe: bool) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let user_id = match resolve_user_id(&admin, args.user_ref.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };

    let data = match admin.get_user_raw(user_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get user"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&data);
    } else {
        let out = json!({
            "id": data.get("id").cloned().unwrap_or(Value::Null),
            "username": data.get("username").cloned().unwrap_or(Value::Null),
            "role": data.get("role").cloned().unwrap_or(Value::Null),
            "telegram_id": data.get("telegram_id").cloned().unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn set_user_role(args: SetUserRoleArgs) -> io::Result<i32> {
    let role = args.role.trim().to_string();
    if role.is_empty() {
        crate::console::err("Role is required.");
        return Ok(2);
    }
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let user_id = match resolve_user_id(&admin, Some(args.user_ref.as_str())) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let out = match admin.update_user_role(user_id, &role) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "update user role"),
    };
    if args.json_out {
        print_json(&out);
    } else {
        crate::console::ok(&format!("User {} role set to {}.", user_id, role));
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn get_grants(args: GetGrantsArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let user_id = if let Some(u) = args.user_ref.as_deref() {
        match resolve_user_id(&admin, Some(u)) {
            Ok(v) => Some(v),
            Err(msg) => {
                crate::console::err(&msg);
                return Ok(2);
            }
        }
    } else {
        None
    };
    let data = match admin.list_grants_raw(user_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list grants"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "id",
        "user_id",
        "server_id",
        "protocol_id",
        "status",
        "expires_at",
        "revoked_at",
    ]);
    for g in items {
        table.add_row(vec![
            value_text(g.get("id")),
            value_text(g.get("user_id")),
            value_text(g.get("server_id")),
            value_text(g.get("protocol_id")),
            value_text(g.get("status")),
            value_text(g.get("expires_at")),
            value_text(g.get("revoked_at")),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_grant(args: GetGrantArgs, describe: bool) -> io::Result<i32> {
    let Some(grant_id) = args.grant_id else {
        crate::console::err("Grant id is required.");
        return Ok(2);
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_grants_raw(None) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list grants"),
    };
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let grant = items
        .into_iter()
        .find(|g| g.get("id").and_then(|v| v.as_i64()) == Some(grant_id));

    let Some(grant) = grant else {
        crate::console::err(&format!("Grant {grant_id} not found."));
        return Ok(2);
    };
    if args.json_out {
        print_json(&grant);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&grant);
    } else {
        let out = json!({
            "id": grant.get("id").cloned().unwrap_or(Value::Null),
            "user_id": grant.get("user_id").cloned().unwrap_or(Value::Null),
            "server_id": grant.get("server_id").cloned().unwrap_or(Value::Null),
            "protocol_id": grant.get("protocol_id").cloned().unwrap_or(Value::Null),
            "status": grant.get("status").cloned().unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn delete_grant(args: DeleteGrantArgs) -> io::Result<i32> {
    let grant_id = if let Some(v) = args.grant_id {
        v
    } else {
        if !std::io::stdin().is_terminal() {
            crate::console::err("Grant id is required in non-interactive mode.");
            return Ok(2);
        }
        let client = client_from_base(args.base_url.as_deref())?;
        let admin = AdminFacade::new(&client);
        select_grant_id(&admin)?
    };

    if !args.force {
        if !std::io::stdin().is_terminal() {
            crate::console::err("Use --force in non-interactive mode.");
            return Ok(2);
        }
        if !ask_yes_no(&format!("Revoke grant {grant_id}?"), false)? {
            crate::console::info("Aborted.");
            return Ok(0);
        }
    }

    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.revoke_grant(grant_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "revoke grant"),
    };
    if args.json_out {
        print_json(&data);
    } else {
        crate::console::ok(&format!("Grant {} revoked.", value_text(data.get("id"))));
    }
    Ok(0)
}

fn resolve_user_id(admin: &AdminFacade<'_>, user_ref: Option<&str>) -> Result<i64, String> {
    let Some(user_ref) = user_ref else {
        if !std::io::stdin().is_terminal() {
            return Err("User reference is required in non-interactive mode.".to_string());
        }
        return select_user_id(admin);
    };
    let trimmed = user_ref.trim();
    if trimmed.is_empty() {
        return Err("User reference cannot be empty.".to_string());
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return trimmed
            .parse::<i64>()
            .map_err(|_| "Invalid user id.".to_string());
    }

    let data = admin
        .list_users_raw(Some(trimmed), Some(100), Some(0))
        .map_err(|e| e.message)?;
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let exact = items.into_iter().find(|u| {
        u.get("username")
            .and_then(|v| v.as_str())
            .map(|v| v.eq_ignore_ascii_case(trimmed))
            .unwrap_or(false)
    });
    exact
        .and_then(|u| u.get("id").and_then(|v| v.as_i64()))
        .ok_or_else(|| format!("User '{}' not found.", trimmed))
}

fn select_user_id(admin: &AdminFacade<'_>) -> Result<i64, String> {
    let data = admin
        .list_users_raw(None, Some(200), Some(0))
        .map_err(|e| e.message)?;
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        return Err("No users found.".to_string());
    }
    let mut labels = Vec::new();
    let mut ids = Vec::new();
    for u in items {
        let id = u.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
        if id <= 0 {
            continue;
        }
        labels.push(format!(
            "{}  {}  ({})",
            id,
            value_text(u.get("username")),
            value_text(u.get("role"))
        ));
        ids.push(id);
    }
    if ids.is_empty() {
        return Err("No valid users found.".to_string());
    }
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select user")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())?;
    Ok(ids[idx])
}

fn select_grant_id(admin: &AdminFacade<'_>) -> io::Result<i64> {
    let data = admin
        .list_grants_raw(None)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.message))?;
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "No grants found."));
    }
    let mut labels = Vec::new();
    let mut ids = Vec::new();
    for g in items {
        let id = g.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
        if id <= 0 {
            continue;
        }
        labels.push(format!(
            "{}  user={}  node={}  status={}",
            id,
            value_text(g.get("user_id")),
            value_text(g.get("server_id")),
            value_text(g.get("status"))
        ));
        ids.push(id);
    }
    if ids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "No valid grants found.",
        ));
    }
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select grant")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(ids[idx])
}

fn value_text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".to_string(),
        Some(Value::String(s)) => {
            if s.trim().is_empty() {
                "-".to_string()
            } else {
                s.to_string()
            }
        }
        Some(other) => other.to_string(),
    }
}

fn client_from_base(base_override: Option<&str>) -> io::Result<ApiClient> {
    let cfg = load_config()?;
    let base = normalize_base_url(base_override.unwrap_or(&cfg.base_url));
    ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn fail_admin(err: ApiError, action: &str) -> io::Result<i32> {
    if err.status_code == 401 || err.status_code == 403 {
        crate::console::err("Unauthorized. Admin access is required.");
    } else {
        crate::console::err(&format!("Failed to {action}: {}", err.message));
    }
    Ok(2)
}

fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    } else {
        println!("{v}");
    }
}

fn ask_yes_no(prompt: &str, default_yes: bool) -> io::Result<bool> {
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(&["Yes", "No"])
        .default(if default_yes { 0 } else { 1 })
        .interact()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(idx == 0)
}
