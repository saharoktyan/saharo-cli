use std::io;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use saharo_sdk::{AdminFacade, ApiClient, ApiError};
use serde_json::Value;

use crate::config::{load_config, normalize_base_url};
use crate::{CreateUserInviteArgs, GetInviteArgs, GetInvitesArgs};

pub fn get_invites(args: GetInvitesArgs) -> io::Result<i32> {
    if args.page < 1 || args.page_size < 1 {
        crate::console::err("--page and --page-size must be >= 1.");
        return Ok(2);
    }
    let offset = (args.page - 1) * args.page_size;
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_invites_raw(args.page_size, offset) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list invites"),
    };

    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    let items = invite_items(&data);
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "id",
        "token",
        "max_uses",
        "uses_count",
        "expires_at",
        "created_at",
    ]);
    for item in items {
        table.add_row(vec![
            value_text(item.get("id")),
            value_text(item.get("token")),
            value_text(item.get("max_uses")),
            value_text(item.get("uses_count")),
            value_text(item.get("expires_at")),
            value_text(item.get("created_at")),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_invite(args: GetInviteArgs, describe: bool) -> io::Result<i32> {
    let invite_ref = match args.invite_ref {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            crate::console::err("Invite id or token is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_invites_raw(200, 0) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list invites"),
    };
    let maybe_id = invite_ref.parse::<i64>().ok();
    let item = invite_items(&data).into_iter().find(|v| {
        if let Some(id) = maybe_id {
            v.get("id").and_then(|x| x.as_i64()) == Some(id)
                || v.get("invite_id").and_then(|x| x.as_i64()) == Some(id)
        } else {
            v.get("token").and_then(|x| x.as_str()) == Some(invite_ref.as_str())
        }
    });

    let Some(invite) = item else {
        crate::console::err(&format!("Invite '{}' not found.", invite_ref));
        return Ok(2);
    };

    if args.json_out {
        print_json(&invite);
        return Ok(0);
    }

    if describe {
        crate::pretty_kv::print_value(&invite);
    } else {
        let out = serde_json::json!({
            "id": invite.get("id").cloned().unwrap_or(Value::Null),
            "token": invite.get("token").cloned().unwrap_or(Value::Null),
            "max_uses": invite.get("max_uses").cloned().unwrap_or(Value::Null),
            "uses_count": invite.get("uses_count").cloned().unwrap_or(Value::Null),
            "expires_at": invite.get("expires_at").cloned().unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn create_user_invite(args: CreateUserInviteArgs) -> io::Result<i32> {
    if args.max_uses < 1 {
        crate::console::err("--max-uses must be >= 1.");
        return Ok(2);
    }
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let out = match admin.create_invite(
        args.duration_days,
        args.perpetual,
        args.note.as_deref(),
        args.max_uses,
        Some(args.expires_in_days),
    ) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "create invite"),
    };
    if args.json_out {
        print_json(&out);
        return Ok(0);
    }
    let token = out.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if token.is_empty() {
        crate::console::ok("User invite created.");
        crate::pretty_kv::print_value(&out);
    } else {
        crate::console::ok("User invite created:");
        println!("{token}");
    }
    Ok(0)
}

fn invite_items(data: &Value) -> Vec<Value> {
    if let Some(arr) = data.as_array() {
        return arr.clone();
    }
    data.get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn value_text(v: Option<&Value>) -> String {
    match v {
        None => "-".to_string(),
        Some(Value::Null) => "-".to_string(),
        Some(Value::String(s)) if s.trim().is_empty() => "-".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn client_from_base(base_url: Option<&str>) -> io::Result<ApiClient> {
    let cfg = load_config()?;
    let base = normalize_base_url(base_url.unwrap_or(&cfg.base_url));
    ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn fail_admin(err: ApiError, action: &str) -> io::Result<i32> {
    crate::console::err(&saharo_sdk::format_admin_error(&err, action));
    Ok(2)
}

fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    } else {
        println!("{v}");
    }
}
