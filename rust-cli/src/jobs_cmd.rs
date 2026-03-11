use std::io;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use serde_json::Value;

use saharo_sdk::ApiClient;
use crate::config::{load_config, normalize_base_url};
use crate::{JobsClearArgs, JobsCommand, JobsCreateArgs, JobsGetArgs, JobsListArgs};

pub fn handle_jobs(command: JobsCommand) -> io::Result<i32> {
    match command {
        JobsCommand::Create(args) => create_job(args),
        JobsCommand::List(args) => list_jobs(args),
        JobsCommand::Get(args) | JobsCommand::Show(args) => get_job(args),
        JobsCommand::Clear(args) => clear_jobs(args),
    }
}

fn create_job(args: JobsCreateArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let job_key = args.job_type.trim().to_lowercase().replace('_', "-");
    let api_type = match job_key.as_str() {
        "restart-service" => "restart_service",
        "start-service" => "start_service",
        "stop-service" => "stop_service",
        "restart-container" => "restart_container",
        "collect-status" => "collect_status",
        "update-agent" => "agent_update",
        _ => {
            err("Invalid job type. Use restart-service, start-service, stop-service, restart-container, collect-status, or update-agent.");
            return Ok(2);
        }
    };

    let mut payload = serde_json::Map::new();
    if matches!(job_key.as_str(), "restart-service" | "start-service" | "stop-service") {
        let Some(service) = args.service.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) else {
            err("--service is required for service jobs.");
            return Ok(2);
        };
        payload.insert("service".to_string(), Value::String(service.to_string()));
    } else if job_key == "restart-container" {
        let Some(container) = args.container.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) else {
            err("--container is required for restart-container.");
            return Ok(2);
        };
        payload.insert("container".to_string(), Value::String(container.to_string()));
    } else if job_key == "update-agent" {
        if let Some(version) = args.version.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            payload.insert("target_version".to_string(), Value::String(version.to_string()));
        }
    }

    let mut server_id = None;
    if let Some(server_ref) = args.server.as_deref() {
        server_id = Some(resolve_server_id(&client, server_ref).map_err(io_other)?);
    }
    if server_id.is_some() && args.agent_id.is_some() {
        err("Use either --server or --agent-id, not both.");
        return Ok(2);
    }

    let data = match client.admin_job_create(server_id, args.agent_id, api_type, Value::Object(payload)) {
        Ok(v) => v,
        Err(e) => {
            if e.status_code == 401 || e.status_code == 403 {
                err("Unauthorized. Admin access is required.");
            } else {
                err(&format!("Failed to create job: {}", e.message));
            }
            return Ok(2);
        }
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    crate::console::ok(&format!(
        "Job created: id={} status={}",
        sval(&data, "id"),
        sval(&data, "status")
    ));
    Ok(0)
}

fn list_jobs(args: JobsListArgs) -> io::Result<i32> {
    if args.page < 1 {
        err("--page must be >= 1.");
        return Ok(2);
    }
    if args.page_size < 1 {
        err("--page-size must be >= 1.");
        return Ok(2);
    }
    let offset = (args.page - 1) * args.page_size;

    let cfg = load_config()?;
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut server_id = None;
    if let Some(server_ref) = args.server.as_deref() {
        server_id = Some(resolve_server_id(&client, server_ref).map_err(io_other)?);
    }

    let data = match client.admin_jobs_list(
        args.status.as_deref(),
        args.agent_id,
        server_id,
        Some(args.page_size),
        Some(offset),
    ) {
        Ok(v) => v,
        Err(e) => {
            if e.status_code == 401 || e.status_code == 403 {
                err("Unauthorized. Admin access is required.");
            } else {
                err(&format!("Failed to list jobs: {}", e.message));
            }
            return Ok(2);
        }
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
        "type",
        "status",
        "agent_id",
        "server_id",
        "created_at",
        "started_at",
        "finished_at",
    ]);
    for j in items {
        let id = sval(&j, "id");
        let jtype = sval(&j, "type");
        let status = sval(&j, "status");
        let agent_id = sval(&j, "agent_id");
        let server_id = j
            .get("payload")
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("server_id"))
            .map(simple)
            .unwrap_or_else(|| "-".to_string());
        let created = sval(&j, "created_at");
        let started = sval(&j, "started_at");
        let finished = sval(&j, "finished_at");
        table.add_row(vec![id, jtype, status, agent_id, server_id, created, started, finished]);
    }
    println!("{table}");
    if let Some(total) = data.get("total").and_then(|v| v.as_i64()) {
        let pages = std::cmp::max(1, ((total + args.page_size - 1) / args.page_size) as i64);
        crate::console::info(&format!("page={}/{} total={}", args.page, pages, total));
    }

    Ok(0)
}

fn get_job(args: JobsGetArgs) -> io::Result<i32> {
    let job_id = match args.job_id {
        Some(v) => v,
        None => {
            err("Job id is required.");
            return Ok(2);
        }
    };

    let cfg = load_config()?;
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let data = match client.admin_job_get(job_id) {
        Ok(v) => v,
        Err(e) => {
            if e.status_code == 404 {
                err(&format!("Job {} not found. Use `saharo jobs get <id>`.", job_id));
            } else if e.status_code == 401 || e.status_code == 403 {
                err("Unauthorized. Admin access is required.");
            } else {
                err(&format!("Failed to fetch job: {}", e.message));
            }
            return Ok(2);
        }
    };

    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    if let Some(obj) = data.as_object() {
        crate::pretty_kv::print_object(obj);
    } else {
        crate::pretty_kv::print_value(&data);
    }
    Ok(0)
}

fn clear_jobs(args: JobsClearArgs) -> io::Result<i32> {
    if !args.yes {
        crate::console::warn("Confirmation required. Re-run with --yes to proceed.");
        return Ok(2);
    }
    let cfg = load_config()?;
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let data = match client.admin_jobs_cleanup(
        args.older_than_days,
        args.status.as_deref(),
        args.server_id,
        args.agent_id,
        args.dry_run,
    ) {
        Ok(v) => v,
        Err(e) => {
            if e.status_code == 401 || e.status_code == 403 {
                err("Unauthorized. Admin access is required.");
            } else {
                err(&format!("Failed to clear jobs: {}", e.message));
            }
            return Ok(2);
        }
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    crate::console::ok(&format!(
        "Matched={} Deleted={}",
        sval(&data, "matched"),
        sval(&data, "deleted")
    ));
    Ok(0)
}

fn resolve_server_id(client: &ApiClient, server_ref: &str) -> Result<i64, String> {
    if server_ref.trim().chars().all(|c| c.is_ascii_digit()) {
        return server_ref
            .trim()
            .parse::<i64>()
            .map_err(|_| "Invalid server id.".to_string());
    }
    let data = client
        .admin_servers_list(Some(server_ref), Some(50), Some(0))
        .map_err(|e| e.message)?;
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let matches = items
        .iter()
        .filter(|s| s.get("name").and_then(|v| v.as_str()) == Some(server_ref))
        .cloned()
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(format!("Server '{}' not found.", server_ref));
    }
    if matches.len() > 1 {
        let ids = matches
            .iter()
            .filter_map(|s| s.get("id").and_then(|v| v.as_i64()).map(|id| id.to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("Multiple servers matched '{}': {}", server_ref, ids));
    }
    matches[0]
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "Invalid server id in response.".to_string())
}

fn io_other(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

fn sval(data: &Value, key: &str) -> String {
    data.get(key).map(simple).unwrap_or_else(|| "-".to_string())
}

fn simple(v: &Value) -> String {
    match v {
        Value::Null => "-".to_string(),
        Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    } else {
        println!("{v}");
    }
}

fn err(msg: &str) {
    crate::console::err(msg);
}
