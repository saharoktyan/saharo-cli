use std::io;
use std::io::IsTerminal;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use saharo_sdk::{
    build_join_request, format_admin_error, format_join_error, parse_job_details, parse_jobs_list,
    parse_node_details, parse_nodes_list, AdminFacade, ApiClient, ApiError, JoinExecutionOptions,
    JoinRequestInput,
};
use serde_json::Value;

use crate::config::{load_config, normalize_base_url};
use crate::{
    ApiLogsArgs, DeleteArgs, DeleteJobsArgs, DeleteNodeArgs, DeleteResource, DescribeArgs,
    DescribeResource, GetArgs, GetJobArgs, GetJobsArgs, GetNodeArgs, GetNodesArgs, GetResource,
    JoinNodeArgs, KubeLogsArgs, LogsResource, NodeLogsArgs, RuntimeLogsArgs,
};

pub fn handle_get(args: GetArgs) -> io::Result<i32> {
    match args.resource {
        GetResource::Nodes(a) => get_nodes(a),
        GetResource::Node(a) => get_node(a, false),
        GetResource::Jobs(a) => get_jobs(a),
        GetResource::Job(a) => get_job(a, false),
        GetResource::Pods(a) => crate::services_cmd::get_pods(a),
        GetResource::Pod(a) => crate::services_cmd::get_pod(a, false),
        GetResource::Deployments(a) => crate::services_cmd::get_deployments(a),
        GetResource::Deployment(a) => crate::services_cmd::get_deployment(a, false),
        GetResource::DeploymentRevisions(a) => crate::services_cmd::get_deployment_revisions(a),
        GetResource::Bindings(a) => crate::services_cmd::get_bindings(a),
        GetResource::Binding(a) => crate::services_cmd::get_binding(a, false),
        GetResource::Users(a) => crate::principal_cmd::get_users(a),
        GetResource::User(a) => crate::principal_cmd::get_user(a, false),
        GetResource::Grants(a) => crate::principal_cmd::get_grants(a),
        GetResource::Grant(a) => crate::principal_cmd::get_grant(a, false),
        GetResource::Invites(a) => crate::invites_cmd::get_invites(a),
        GetResource::Invite(a) => crate::invites_cmd::get_invite(a, false),
        GetResource::Roles(a) => crate::roles_cmd::get_roles(a),
        GetResource::Role(a) => crate::roles_cmd::get_role(a, false),
        GetResource::RoleBindings(a) => crate::roles_cmd::get_role_bindings(a),
        GetResource::RoleBinding(a) => crate::roles_cmd::get_role_binding(a, false),
        GetResource::Releases(a) => crate::updates_cmd::get_releases(a),
        GetResource::Release(a) => crate::updates_cmd::get_release(a, false),
    }
}

pub fn handle_describe(args: DescribeArgs) -> io::Result<i32> {
    match args.resource {
        DescribeResource::Node(a) => get_node(a, true),
        DescribeResource::Job(a) => get_job(a, true),
        DescribeResource::Pod(a) => crate::services_cmd::get_pod(a, true),
        DescribeResource::Deployment(a) => crate::services_cmd::get_deployment(a, true),
        DescribeResource::Binding(a) => crate::services_cmd::get_binding(a, true),
        DescribeResource::BindingDrift(a) => crate::services_cmd::describe_binding_drift(a),
        DescribeResource::User(a) => crate::principal_cmd::get_user(a, true),
        DescribeResource::Grant(a) => crate::principal_cmd::get_grant(a, true),
        DescribeResource::Invite(a) => crate::invites_cmd::get_invite(a, true),
        DescribeResource::Role(a) => crate::roles_cmd::get_role(a, true),
        DescribeResource::RoleBinding(a) => crate::roles_cmd::get_role_binding(a, true),
        DescribeResource::Release(a) => crate::updates_cmd::get_release(a, true),
    }
}

pub fn handle_delete(args: DeleteArgs) -> io::Result<i32> {
    match args.resource {
        DeleteResource::Node(a) => delete_node(a),
        DeleteResource::Grant(a) => crate::principal_cmd::delete_grant(a),
        DeleteResource::Jobs(a) => delete_jobs(a),
        DeleteResource::Host(a) => crate::portal_cmd::delete_host(a),
    }
}

pub fn handle_logs(args: KubeLogsArgs) -> io::Result<i32> {
    match args.resource {
        LogsResource::Node(a) => logs_node(a),
        LogsResource::Api(a) => logs_api(a),
        LogsResource::Runtime(a) => logs_runtime(a),
    }
}

pub fn handle_join(args: JoinNodeArgs) -> io::Result<i32> {
    let resolved = resolve_join_inputs(&args)?;
    let cfg = load_config()?;
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let agent_api_base = resolve_agent_api_base(&base_url, args.api_url.as_deref(), resolved.local)?;
    if !args.json_out {
        print_join_plan(&resolved, args.dry_run);
        crate::console::info(&format!("  agent_api_base: {}", agent_api_base));
    }
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let admin = AdminFacade::new(&client);

    let payload = build_join_request(JoinRequestInput {
        name: resolved.name.clone(),
        host: resolved.host.clone(),
        note: resolved.note.clone(),
        ssh_target: resolved.ssh_target.clone(),
        ssh_port: resolved.ssh_port,
        ssh_key: resolved.ssh_key.clone(),
        ssh_password_prompt: resolved.ssh_password_prompt,
        ssh_password: resolved.ssh_password.clone(),
        sudo: resolved.sudo,
        local: resolved.local,
        local_path: resolved.local_path.clone(),
        sudo_password_prompt: resolved.sudo_password_prompt,
        sudo_password: resolved.sudo_password.clone(),
        provision_mode: Some(resolved.provision_mode.clone()),
        public_api_base: Some(agent_api_base.clone()),
        include_bootstrap: resolved.provision_mode == "client",
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if args.dry_run {
        crate::console::warn("Dry-run: node join request would be sent to Host API.");
        let dry_payload = serde_json::to_value(&payload).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to render join payload: {e}"),
            )
        })?;
        print_json(&dry_payload);
        return Ok(0);
    }

    let wait = resolved.wait && resolved.provision_mode != "client";
    if wait {
        crate::console::info(&format!(
            "Waiting for join job completion (timeout={}s, interval={}s)",
            args.wait_timeout.max(1),
            args.wait_interval.max(1)
        ));
    }
    let join_result = match admin.join_node(
        &payload,
        JoinExecutionOptions {
            wait,
            timeout: Duration::from_secs(args.wait_timeout.max(1) as u64),
            interval: Duration::from_secs(args.wait_interval.max(1) as u64),
        },
        |jid, status, elapsed| {
            crate::console::info(&format!(
                "job {} status={} (elapsed={}s)",
                jid,
                if status.is_empty() { "unknown" } else { status },
                elapsed.as_secs()
            ));
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            crate::console::err(&format_join_error(&e));
            return Ok(2);
        }
    };

    if resolved.provision_mode == "client" {
        provision_node_via_client_ssh(&resolved, &join_result.response, &agent_api_base)?;
    }

    if wait {
        if let Some(job_id) = join_result.job_id {
            if join_result.timed_out {
                crate::console::warn(&format!(
                    "Job {} did not finish before timeout ({}s).",
                    job_id,
                    args.wait_timeout.max(1)
                ));
            }
            if join_result.job_status.as_deref() != Some("succeeded") {
                crate::console::err(&format!(
                    "Join job {} finished with status={}",
                    job_id,
                    join_result
                        .job_status
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string())
                ));
                return Ok(2);
            }
        }
    }

    let mut out = join_result.response.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "job_status".to_string(),
            join_result
                .job_status
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    if args.json_out {
        print_json(&out);
        return Ok(0);
    }
    crate::console::ok("Node join started.");
    crate::pretty_kv::print_value(&out);
    Ok(0)
}

fn get_nodes(args: GetNodesArgs) -> io::Result<i32> {
    if args.page < 1 || args.page_size < 1 {
        crate::console::err("--page and --page-size must be >= 1.");
        return Ok(2);
    }
    let offset = (args.page - 1) * args.page_size;
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_nodes_raw(args.q.as_deref(), Some(args.page_size), Some(offset)) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to list nodes"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "name", "host", "status", "missed"]);
    for n in parse_nodes_list(&data) {
        table.add_row(vec![
            n.id.map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            n.name.unwrap_or_else(|| "-".to_string()),
            n.host.unwrap_or_else(|| "-".to_string()),
            n.status.unwrap_or_else(|| "-".to_string()),
            n.missed_heartbeats
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ]);
    }
    println!("{table}");
    Ok(0)
}

fn get_node(args: GetNodeArgs, describe: bool) -> io::Result<i32> {
    let node_ref = match args.node_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Node ID or exact name is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match admin.resolve_node_id(&node_ref) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let node = match admin.get_node_raw(node_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to fetch node"),
    };
    if args.json_out {
        print_json(&node);
        return Ok(0);
    }
    let details = parse_node_details(&node);
    if describe {
        let out = serde_json::to_value(&details).unwrap_or(node);
        crate::pretty_kv::print_value(&out);
    } else {
        let summary = serde_json::json!({
            "id": details.id,
            "name": details.name,
            "host": details.host,
            "status": details.status,
        });
        crate::pretty_kv::print_value(&summary);
    }
    Ok(0)
}

fn get_jobs(args: GetJobsArgs) -> io::Result<i32> {
    if args.page < 1 || args.page_size < 1 {
        crate::console::err("--page and --page-size must be >= 1.");
        return Ok(2);
    }
    let offset = (args.page - 1) * args.page_size;
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let mut node_id = None;
    if let Some(node_ref) = args.node.as_deref() {
        node_id = Some(
            admin
                .resolve_node_id(node_ref)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        );
    }
    let data = match admin.list_jobs_raw(
        args.status.as_deref(),
        args.agent_id,
        node_id,
        Some(args.page_size),
        Some(offset),
    ) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to list jobs"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "id",
        "type",
        "status",
        "agent_id",
        "node_id",
        "created_at",
        "started_at",
        "finished_at",
    ]);
    for j in parse_jobs_list(&data) {
        table.add_row(vec![
            j.id.map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            j.job_type.unwrap_or_else(|| "-".to_string()),
            j.status.unwrap_or_else(|| "-".to_string()),
            j.agent_id
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            j.node_id.unwrap_or_else(|| "-".to_string()),
            j.created_at.unwrap_or_else(|| "-".to_string()),
            j.started_at.unwrap_or_else(|| "-".to_string()),
            j.finished_at.unwrap_or_else(|| "-".to_string()),
        ]);
    }
    println!("{table}");
    Ok(0)
}

fn get_job(args: GetJobArgs, describe: bool) -> io::Result<i32> {
    let Some(job_id) = args.job_id else {
        crate::console::err("Job id is required.");
        return Ok(2);
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let job = match admin.get_job_raw(job_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to fetch job"),
    };
    if args.json_out {
        print_json(&job);
        return Ok(0);
    }
    let details = parse_job_details(&job);
    if describe {
        let out = serde_json::to_value(&details).unwrap_or(job);
        crate::pretty_kv::print_value(&out);
    } else {
        let summary = serde_json::json!({
            "id": details.id,
            "type": details.job_type,
            "status": details.status,
            "created_at": details.created_at,
        });
        crate::pretty_kv::print_value(&summary);
    }
    Ok(0)
}

fn delete_node(args: DeleteNodeArgs) -> io::Result<i32> {
    let node_ref = match args.node_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Node ID or exact name is required.");
            return Ok(2);
        }
    };
    let force = args.force && !args.no_force;
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match admin.resolve_node_id(&node_ref) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let data = match admin.delete_node(node_id, force) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to delete node"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    crate::console::ok(&format!("Node {} deleted.", node_id));
    Ok(0)
}

fn delete_jobs(args: DeleteJobsArgs) -> io::Result<i32> {
    if !args.yes && !args.dry_run {
        crate::console::err("Use --yes to confirm job deletion (or --dry-run).");
        return Ok(2);
    }
    let client = client_from_base(args.base_url.as_deref())?;
    let data = match client.admin_jobs_cleanup(
        args.older_than_days,
        args.status.as_deref(),
        args.node_id,
        args.agent_id,
        args.dry_run,
    ) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to delete jobs"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    if args.dry_run {
        crate::console::ok("Jobs cleanup dry-run completed.");
    } else {
        crate::console::ok("Jobs cleanup completed.");
    }
    crate::pretty_kv::print_value(&data);
    Ok(0)
}

fn logs_node(args: NodeLogsArgs) -> io::Result<i32> {
    let node_ref = match args.node_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Node ID or exact name is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match admin.resolve_node_id(&node_ref) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let data = match admin.node_logs(node_id, args.lines.max(1)) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to fetch node logs"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    if let Some(logs) = data
        .get("logs")
        .or_else(|| data.get("raw"))
        .and_then(|v| v.as_str())
    {
        println!("{logs}");
    } else {
        print_json(&data);
    }
    Ok(0)
}

fn logs_api(args: ApiLogsArgs) -> io::Result<i32> {
    let lines = args.lines.max(1).to_string();
    let mut cmd = Command::new("docker");
    cmd.arg("logs").arg("--tail").arg(lines);
    if args.follow {
        cmd.arg("--follow");
    }
    cmd.arg("saharo_api");
    if args.follow {
        let status = cmd.status()?;
        if !status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "docker logs failed"));
        }
        return Ok(0);
    }
    let out = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(io::Error::new(
            io::ErrorKind::Other,
            if stderr.is_empty() {
                "failed to fetch API logs".to_string()
            } else {
                stderr
            },
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.trim().is_empty() {
        println!("{stdout}");
    }
    Ok(0)
}

fn logs_runtime(args: RuntimeLogsArgs) -> io::Result<i32> {
    let node_ref = match args.node_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Node ID or exact name is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match admin.resolve_node_id(&node_ref) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let node = match admin.get_node_raw(node_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "Failed to fetch node"),
    };
    let Some(agent_id) = node.get("agent_id").and_then(|v| v.as_i64()) else {
        crate::console::err("Node is not attached to a runtime.");
        return Ok(2);
    };
    let containers = vec!["saharo_agent".to_string()];
    let mut previous = String::new();
    loop {
        let data = match admin.get_agent_logs(agent_id, &containers, args.lines.max(1)) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "Failed to fetch runtime logs"),
        };
        if args.json_out {
            print_json(&data);
            return Ok(0);
        }
        let current = data
            .get("logs")
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("saharo_agent"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if args.follow {
            if !previous.is_empty() && current.starts_with(&previous) {
                let delta = &current[previous.len()..];
                if !delta.trim().is_empty() {
                    print!("{delta}");
                }
            } else if !current.trim().is_empty() {
                print!("{current}");
            }
            previous = current;
            thread::sleep(Duration::from_secs(2));
            continue;
        } else {
            if !current.trim().is_empty() {
                println!("{current}");
            }
            return Ok(0);
        }
    }
}

fn client_from_base(base_url: Option<&str>) -> io::Result<ApiClient> {
    let cfg = load_config()?;
    let base = normalize_base_url(base_url.unwrap_or(&cfg.base_url));
    ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

struct ResolvedJoinArgs {
    name: String,
    host: String,
    note: Option<String>,
    ssh_target: Option<String>,
    ssh_user: String,
    ssh_port: i64,
    ssh_key: Option<String>,
    ssh_password_prompt: bool,
    ssh_password: Option<String>,
    sudo: bool,
    sudo_password_prompt: bool,
    sudo_password: Option<String>,
    local: bool,
    local_path: Option<String>,
    provision_mode: String,
    wait: bool,
}

fn resolve_join_inputs(args: &JoinNodeArgs) -> io::Result<ResolvedJoinArgs> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let theme = ColorfulTheme::default();
    let mut name = args.name.clone().unwrap_or_default().trim().to_string();
    let mut host = args.host.clone().unwrap_or_default().trim().to_string();
    let mut note = args
        .note
        .clone()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    let mut ssh_target = args
        .ssh_target
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut ssh_user = args.ssh_user.trim().to_string();
    if ssh_user.is_empty() {
        ssh_user = "root".to_string();
    }
    let mut ssh_port = args.ssh_port.max(1);
    let mut ssh_key = args
        .ssh_key
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut ssh_password_prompt = args.ssh_password_prompt;
    let mut ssh_password: Option<String> = None;
    let mut sudo = args.sudo;
    let mut sudo_password_prompt = args.sudo_password_prompt;
    let mut sudo_password: Option<String> = None;
    let mut local_path = args
        .local_path
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut provision_mode = args.provision_mode.trim().to_lowercase();
    let wait = args.wait && !args.no_wait;

    let explicit_remote =
        ssh_target.is_some() || ssh_key.is_some() || ssh_password_prompt || args.ssh_port != 22;
    if args.local && explicit_remote {
        crate::console::err("Conflicting join mode: cannot combine --local with SSH options.");
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conflicting join mode",
        ));
    }
    let mut local = args.local;

    if (name.is_empty() || host.is_empty()) && !interactive {
        crate::console::err(
            "Missing required join args in non-interactive mode. Provide --name and --host.",
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing join args",
        ));
    }
    if name.is_empty() {
        name = Input::with_theme(&theme)
            .with_prompt("Node name")
            .interact_text()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    }
    if host.is_empty() {
        host = Input::with_theme(&theme)
            .with_prompt("Node host (IP or DNS)")
            .interact_text()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    }
    if note.is_none() && interactive {
        let value: String = Input::with_theme(&theme)
            .with_prompt("Note (optional)")
            .allow_empty(true)
            .interact_text()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            note = Some(trimmed);
        }
    }

    if !args.local && !explicit_remote && interactive {
        let mode = Select::with_theme(&theme)
            .with_prompt("Join mode")
            .items(&["SSH remote host", "Local machine"])
            .default(0)
            .interact()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        local = mode == 1;
    }

    if local {
        if local_path.is_none() && interactive {
            let value: String = Input::with_theme(&theme)
                .with_prompt("Local install path")
                .default("/opt/saharo/agent".to_string())
                .interact_text()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                local_path = Some(trimmed);
            }
        }
    } else {
        if ssh_target.is_none() {
            if !interactive {
                ssh_target = Some(format!("{}@{}", ssh_user, host));
            } else {
                let host_value: String = Input::with_theme(&theme)
                    .with_prompt("SSH host")
                    .default(host.clone())
                    .interact_text()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let ssh_host = host_value.trim().to_string();
                let user_value: String = Input::with_theme(&theme)
                    .with_prompt("SSH user")
                    .default("root".to_string())
                    .interact_text()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                ssh_user = user_value.trim().to_string();
                ssh_target = Some(format!("{}@{}", ssh_user, ssh_host));
            }
        } else if interactive && ssh_target.as_ref().is_some_and(|v| !v.contains('@')) {
            let user_value: String = Input::with_theme(&theme)
                .with_prompt("SSH user")
                .default("root".to_string())
                .interact_text()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            ssh_user = user_value.trim().to_string();
            ssh_target = Some(format!(
                "{}@{}",
                ssh_user,
                ssh_target.as_deref().unwrap_or("")
            ));
        }
        if interactive && args.ssh_port == 22 {
            let value: String = Input::with_theme(&theme)
                .with_prompt("SSH port")
                .default("22".to_string())
                .interact_text()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let trimmed = value.trim();
            ssh_port = trimmed
                .parse::<i64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ssh port"))?;
        }
        ssh_port = ssh_port.max(1);

        if interactive && ssh_key.is_none() && !ssh_password_prompt {
            let auth_mode = Select::with_theme(&theme)
                .with_prompt("SSH auth mode")
                .items(&["SSH key (recommended)", "Password prompt"])
                .default(0)
                .interact()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            if auth_mode == 1 {
                ssh_password_prompt = true;
            } else {
                let key_value: String = Input::with_theme(&theme)
                    .with_prompt("SSH private key path")
                    .default("~/.ssh/id_ed25519".to_string())
                    .interact_text()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let trimmed = key_value.trim().to_string();
                if !trimmed.is_empty() {
                    ssh_key = Some(trimmed);
                }
            }
        }
        if ssh_password_prompt {
            if !interactive {
                crate::console::err("`--password` requires interactive TTY mode.");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "password prompt requires interactive tty",
                ));
            }
            ssh_password = Some(
                Password::with_theme(&theme)
                    .with_prompt("SSH password")
                    .allow_empty_password(false)
                    .interact()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
            );
        }
    }

    if !sudo && interactive {
        sudo = ask_yes_no(&theme, "Use sudo on target host?", false)?;
    }
    if sudo && !sudo_password_prompt && interactive {
        sudo_password_prompt = ask_yes_no(&theme, "Prompt for sudo password?", false)?;
    }
    if sudo && sudo_password_prompt {
        if !interactive {
            crate::console::err("`--sudo-password` requires interactive TTY mode.");
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sudo password prompt requires interactive tty",
            ));
        }
        sudo_password = Some(
            Password::with_theme(&theme)
                .with_prompt("Sudo password")
                .allow_empty_password(false)
                .interact()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
        );
    }

    if name.trim().is_empty() || host.trim().is_empty() {
        crate::console::err("--name and --host are required.");
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing join args",
        ));
    }
    if provision_mode.is_empty() {
        provision_mode = "auto".to_string();
    }
    if !matches!(provision_mode.as_str(), "auto" | "client" | "server") {
        crate::console::err("Invalid --provision-mode. Use: auto, client, server.");
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid provision mode",
        ));
    }
    if provision_mode == "auto" {
        provision_mode = if local {
            "client".to_string()
        } else if ssh_password_prompt || sudo_password_prompt {
            "server".to_string()
        } else {
            "client".to_string()
        };
    }
    if !local {
        if let Some(target) = ssh_target.as_mut() {
            let normalized = target.trim().to_string();
            if !normalized.contains('@') {
                *target = format!("{}@{}", ssh_user, normalized);
            } else {
                *target = normalized;
            }
            if let Some((user, _)) = target.split_once('@') {
                if !user.trim().is_empty() {
                    ssh_user = user.trim().to_string();
                }
            }
        }
    }
    Ok(ResolvedJoinArgs {
        name,
        host,
        note,
        ssh_target,
        ssh_user,
        ssh_port,
        ssh_key,
        ssh_password_prompt,
        ssh_password,
        sudo,
        sudo_password_prompt,
        sudo_password,
        local,
        local_path,
        provision_mode,
        wait,
    })
}

fn print_join_plan(args: &ResolvedJoinArgs, dry_run: bool) {
    crate::console::info("Join plan:");
    crate::console::info(&format!("  node: {} ({})", args.name, args.host));
    crate::console::info(&format!(
        "  mode: {}",
        if args.local { "local" } else { "ssh" }
    ));
    crate::console::info(&format!("  provision_mode: {}", args.provision_mode));
    if args.local {
        crate::console::info(&format!(
            "  local_path: {}",
            args.local_path.clone().unwrap_or_else(|| "-".to_string())
        ));
    } else {
        crate::console::info(&format!(
            "  ssh: {}:{}",
            args.ssh_target.clone().unwrap_or_else(|| args.host.clone()),
            args.ssh_port
        ));
        crate::console::info(&format!("  ssh_user: {}", args.ssh_user));
        crate::console::info(&format!(
            "  auth: {}",
            if args.ssh_password_prompt {
                "password_prompt"
            } else if args.ssh_key.is_some() {
                "ssh_key"
            } else {
                "default_ssh_agent_or_key"
            }
        ));
    }
    crate::console::info(&format!(
        "  sudo: {}",
        if args.sudo { "enabled" } else { "disabled" }
    ));
    if let Some(note) = args.note.as_ref() {
        crate::console::info(&format!("  note: {}", note));
    }
    if dry_run {
        crate::console::info("  dry_run: enabled");
    }
}

fn fail_admin(err: ApiError, msg: &str) -> io::Result<i32> {
    let action = msg.strip_prefix("Failed to ").unwrap_or(msg).to_lowercase();
    crate::console::err(&format_admin_error(&err, action.as_str()));
    Ok(2)
}

fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    } else {
        println!("{v}");
    }
}

fn ask_yes_no(theme: &ColorfulTheme, prompt: &str, default_yes: bool) -> io::Result<bool> {
    let idx = Select::with_theme(theme)
        .with_prompt(prompt)
        .items(&["Yes", "No"])
        .default(if default_yes { 0 } else { 1 })
        .interact()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(idx == 0)
}

fn provision_node_via_client_ssh(
    args: &ResolvedJoinArgs,
    response: &Value,
    default_api_base: &str,
) -> io::Result<()> {
    if args.local {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client provision in local mode is not implemented yet",
        ));
    }
    if args.ssh_password_prompt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client provision with ssh password prompt is not supported; use --provision-mode server",
        ));
    }
    let bootstrap = response
        .get("bootstrap")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "missing bootstrap payload in join response",
            )
        })?;
    let mut api_base = bootstrap
        .get("api_base")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if api_base.is_empty() {
        api_base = default_api_base.trim().trim_end_matches('/').to_string();
    }
    let invite = bootstrap
        .get("agent_invite")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if api_base.is_empty() || invite.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "bootstrap payload is missing api_base or agent_invite",
        ));
    }
    let provisioning = response
        .get("provisioning")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let registry = provisioning
        .get("registry_url")
        .and_then(|v| v.as_str())
        .unwrap_or("registry.saharoktyan.ru")
        .trim()
        .to_string();
    let tag = provisioning
        .get("agent_tag")
        .and_then(|v| v.as_str())
        .unwrap_or("latest")
        .trim()
        .to_string();
    let ssh_target = args
        .ssh_target
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing ssh target"))?;
    let base_dir = "/opt/saharo/agent";
    let compose_path = format!("{base_dir}/docker-compose.yml");
    let env_path = format!("{base_dir}/.env");
    let compose = render_agent_compose(&registry, &tag);
    let env = format!(
        "AGENT_API_BASE={}\nSAHARO_AGENT_INVITE={}\nSAHARO_AGENT_ALLOW_INLINE_SCRIPTS=1\nSAHARO_CONTROL_PLANE_GRPC_ENABLED=1\nSAHARO_CONTROL_PLANE_GRPC_TARGET={}\n",
        api_base,
        invite,
        infer_grpc_target(&api_base),
    );
    run_ssh_remote(
        &ssh_target,
        args.ssh_port,
        args.ssh_key.as_deref(),
        args.sudo,
        &format!("mkdir -p {}", shell_quote(base_dir)),
    )?;
    write_remote_file(
        &ssh_target,
        args.ssh_port,
        args.ssh_key.as_deref(),
        args.sudo,
        &compose_path,
        &compose,
    )?;
    write_remote_file(
        &ssh_target,
        args.ssh_port,
        args.ssh_key.as_deref(),
        args.sudo,
        &env_path,
        &env,
    )?;
    run_ssh_remote(
        &ssh_target,
        args.ssh_port,
        args.ssh_key.as_deref(),
        args.sudo,
        &format!("chmod 600 {}", shell_quote(&env_path)),
    )?;
    let compose_probe = run_ssh_capture(
        &ssh_target,
        args.ssh_port,
        args.ssh_key.as_deref(),
        args.sudo,
        "docker compose version >/dev/null 2>&1 && echo docker-compose-plugin || echo docker-compose",
    )?;
    let compose_cmd = if compose_probe.contains("docker-compose-plugin") {
        "docker compose"
    } else {
        "docker-compose"
    };
    run_ssh_remote(
        &ssh_target,
        args.ssh_port,
        args.ssh_key.as_deref(),
        args.sudo,
        &format!(
            "cd {} && {} pull && {} up -d",
            shell_quote(base_dir),
            compose_cmd,
            compose_cmd
        ),
    )?;
    crate::console::ok("Client-side agent provision completed.");
    Ok(())
}

fn write_remote_file(
    ssh_target: &str,
    port: i64,
    ssh_key: Option<&str>,
    sudo: bool,
    path: &str,
    content: &str,
) -> io::Result<()> {
    let encoded = BASE64.encode(content.as_bytes());
    run_ssh_remote(
        ssh_target,
        port,
        ssh_key,
        sudo,
        &format!(
            "printf '%s' {} | base64 -d > {}",
            shell_quote(&encoded),
            shell_quote(path)
        ),
    )
}

fn run_ssh_capture(
    ssh_target: &str,
    port: i64,
    ssh_key: Option<&str>,
    sudo: bool,
    command: &str,
) -> io::Result<String> {
    let wrapped = if sudo {
        format!("sudo sh -lc {}", shell_quote(command))
    } else {
        command.to_string()
    };
    let output = ssh_command(ssh_target, port, ssh_key, &wrapped).output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

fn run_ssh_remote(
    ssh_target: &str,
    port: i64,
    ssh_key: Option<&str>,
    sudo: bool,
    command: &str,
) -> io::Result<()> {
    let wrapped = if sudo {
        format!("sudo sh -lc {}", shell_quote(command))
    } else {
        command.to_string()
    };
    let status = ssh_command(ssh_target, port, ssh_key, &wrapped).status()?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("remote command failed: {}", command),
    ))
}

fn ssh_command(ssh_target: &str, port: i64, ssh_key: Option<&str>, command: &str) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-p").arg(port.to_string());
    if let Some(key) = ssh_key.filter(|v| !v.trim().is_empty()) {
        cmd.arg("-i").arg(expand_home(key));
    }
    cmd.arg(ssh_target);
    cmd.arg(command);
    cmd
}

fn expand_home(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn infer_grpc_target(api_base: &str) -> String {
    let without_scheme = api_base
        .strip_prefix("https://")
        .or_else(|| api_base.strip_prefix("http://"))
        .unwrap_or(api_base);
    let host_port = without_scheme.split('/').next().unwrap_or("localhost");
    let host = host_port.split(':').next().unwrap_or("localhost");
    let formatted = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    format!("{formatted}:50051")
}

fn is_local_base_url(url: &str) -> bool {
    let normalized = normalize_base_url(url);
    let raw = normalized
        .strip_prefix("http://")
        .or_else(|| normalized.strip_prefix("https://"))
        .unwrap_or(&normalized);
    let host = raw.split('/').next().unwrap_or("").split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0")
}

fn resolve_agent_api_base(
    base_url: &str,
    api_url_override: Option<&str>,
    local_mode: bool,
) -> io::Result<String> {
    if local_mode {
        return Ok(normalize_base_url(api_url_override.unwrap_or(base_url)));
    }
    let resolved = normalize_base_url(api_url_override.unwrap_or(base_url));
    if is_local_base_url(&resolved) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "API base_url points to localhost and is unreachable from remote node; pass --api-url with public host",
        ));
    }
    Ok(resolved)
}

fn render_agent_compose(registry: &str, tag: &str) -> String {
    let image = format!("{registry}/saharo/v1/agent:{tag}");
    format!(
        "services:\n  http-agent:\n    image: {}\n    container_name: saharo_agent\n    restart: unless-stopped\n    env_file:\n      - ./.env\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n      - agent_data:/data\n      - /opt/saharo/services/amnezia-awg/conf:/opt/saharo/services/amnezia-awg/conf\n      - /opt/saharo/services:/opt/saharo/services\n\nvolumes:\n  agent_data:\n",
        image
    )
}
