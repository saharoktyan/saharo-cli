use std::fs;
use std::io;
use std::io::IsTerminal;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use dialoguer::{theme::ColorfulTheme, Select};
use saharo_sdk::{AdminFacade, ApiClient, ApiError};
use serde_json::{json, Map, Value};

use crate::config::{load_config, normalize_base_url};
use crate::{
    ApplyArgs, AssignDeploymentArgs, GetBindingArgs, GetBindingDriftArgs, GetBindingsArgs,
    GetDeploymentArgs, GetDeploymentRevisionsArgs, GetDeploymentsArgs, GetPodArgs, GetPodsArgs,
    ReconcileBindingsArgs, UnassignDeploymentArgs,
};

pub fn get_pods(args: GetPodsArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_pods_raw() {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list pods"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let rows = as_array(&data);
    if rows.is_empty() {
        crate::console::info("No pods found.");
        return Ok(0);
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "name", "display_name", "project", "created_at"]);
    for row in rows {
        table.add_row(vec![
            field_text(&row, "id"),
            field_text(&row, "name"),
            field_text(&row, "display_name"),
            field_text(&row, "project"),
            field_text(&row, "created_at"),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_pod(args: GetPodArgs, describe: bool) -> io::Result<i32> {
    let pod_ref = match args.pod_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Pod ID or name is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let pod_id = match admin.resolve_pod_id(pod_ref.trim()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let pod = match admin.get_pod_raw(pod_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get pod"),
    };
    if args.json_out {
        print_json(&pod);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&pod);
    } else {
        let out = json!({
            "id": pod.get("id").cloned().unwrap_or(Value::Null),
            "name": pod.get("name").cloned().unwrap_or(Value::Null),
            "display_name": pod.get("display_name").cloned().unwrap_or(Value::Null),
            "project": pod.get("project").cloned().unwrap_or(Value::Null),
            "updated_at": pod.get("updated_at").cloned().unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn get_deployments(args: GetDeploymentsArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_deployments_raw(args.enabled_only) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list deployments"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let rows = as_array(&data);
    if rows.is_empty() {
        crate::console::info("No deployments found.");
        return Ok(0);
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "name", "display_name", "project", "status", "created_at"]);
    for row in rows {
        table.add_row(vec![
            field_text(&row, "id"),
            field_text(&row, "name"),
            field_text(&row, "display_name"),
            field_text(&row, "project"),
            if row.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            },
            field_text(&row, "created_at"),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_deployment(args: GetDeploymentArgs, describe: bool) -> io::Result<i32> {
    let deployment_ref = match args.deployment_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Deployment ID or name is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let deployment_id = match admin.resolve_deployment_id(deployment_ref.trim()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let deployment = match admin.get_deployment_raw(deployment_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get deployment"),
    };
    if args.json_out {
        print_json(&deployment);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&deployment);
    } else {
        let out = json!({
            "id": deployment.get("id").cloned().unwrap_or(Value::Null),
            "name": deployment.get("name").cloned().unwrap_or(Value::Null),
            "display_name": deployment.get("display_name").cloned().unwrap_or(Value::Null),
            "project": deployment.get("project").cloned().unwrap_or(Value::Null),
            "enabled": deployment.get("enabled").cloned().unwrap_or(Value::Null),
            "updated_at": deployment.get("updated_at").cloned().unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn get_deployment_revisions(args: GetDeploymentRevisionsArgs) -> io::Result<i32> {
    let deployment_ref = match args.deployment_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Deployment ID or name is required.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let deployment_id = match admin.resolve_deployment_id(deployment_ref.trim()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let deployment = match admin.get_deployment_raw(deployment_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "resolve deployment"),
    };
    let deployment_name = deployment.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if deployment_name.is_empty() {
        crate::console::err("Deployment name is missing in API response.");
        return Ok(2);
    }
    let data = match admin.list_deployment_revisions_raw(deployment_name, args.limit) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list deployment revisions"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let rows = as_array(&data);
    if rows.is_empty() {
        crate::console::info("No deployment revisions found.");
        return Ok(0);
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "deployment", "revision", "note", "created_at"]);
    for row in rows {
        table.add_row(vec![
            field_text(&row, "id"),
            field_text(&row, "deployment_name"),
            field_text(&row, "revision"),
            field_text(&row, "note"),
            field_text(&row, "created_at"),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_bindings(args: GetBindingsArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let server_id = match args.node.as_deref() {
        Some(node_ref) if !node_ref.trim().is_empty() => match admin.resolve_node_id(node_ref.trim()) {
            Ok(v) => Some(v),
            Err(msg) => {
                crate::console::err(&msg);
                return Ok(2);
            }
        },
        _ => None,
    };
    let data = match admin.list_bindings_raw(args.binding_kind.as_deref(), server_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list bindings"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let rows = as_array(&data);
    if rows.is_empty() {
        crate::console::info("No bindings found.");
        return Ok(0);
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "name", "node", "deployment", "kind", "state", "replicas"]);
    for row in rows {
        table.add_row(vec![
            field_text(&row, "id"),
            field_text(&row, "name"),
            field_text(&row, "server_id"),
            field_text(&row, "deployment_name"),
            field_text(&row, "binding_kind"),
            field_text(&row, "state"),
            field_text(&row, "replicas"),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_binding(args: GetBindingArgs, describe: bool) -> io::Result<i32> {
    let binding_ref = match args.binding_ref {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            crate::console::err("Binding ID is required.");
            return Ok(2);
        }
    };
    if !binding_ref.chars().all(|c| c.is_ascii_digit()) {
        crate::console::err("Binding lookup currently supports only numeric IDs.");
        return Ok(2);
    }
    let binding_id = match binding_ref.parse::<i64>() {
        Ok(v) => v,
        Err(_) => {
            crate::console::err("Invalid binding ID.");
            return Ok(2);
        }
    };
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let binding = match admin.get_binding_raw(binding_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get binding"),
    };
    if args.json_out {
        print_json(&binding);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&binding);
    } else {
        let out = json!({
            "id": binding.get("id").cloned().unwrap_or(Value::Null),
            "name": binding.get("name").cloned().unwrap_or(Value::Null),
            "server_id": binding.get("server_id").cloned().unwrap_or(Value::Null),
            "deployment_name": binding.get("deployment_name").cloned().unwrap_or(Value::Null),
            "binding_kind": binding.get("binding_kind").cloned().unwrap_or(Value::Null),
            "state": binding.get("state").cloned().unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn apply_manifest_file(args: ApplyArgs) -> io::Result<i32> {
    let file = args.file.trim();
    if file.is_empty() {
        crate::console::err("Use `saharoctl apply -f <file>`.");
        return Ok(2);
    }

    let yaml_content = fs::read_to_string(file)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to read file: {e}")))?;
    let parsed = serde_yaml::from_str::<serde_yaml::Value>(&yaml_content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid YAML: {e}")))?;
    let map = parsed.as_mapping().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid YAML: top-level object is required",
        )
    })?;

    let api_version = mapping_string(map, "apiVersion");
    let kind = mapping_string(map, "kind");

    let api_version = match api_version {
        Some(v) => v,
        None => {
            crate::console::err("Manifest must include non-empty `apiVersion`.");
            return Ok(2);
        }
    };
    let kind = match kind {
        Some(v) => v,
        None => {
            crate::console::err("Manifest must include non-empty `kind`.");
            return Ok(2);
        }
    };
    if api_version != "saharo.io/v1alpha1" {
        crate::console::err(&format!(
            "Unsupported apiVersion `{api_version}`. Expected `saharo.io/v1alpha1`."
        ));
        return Ok(2);
    }
    if !matches!(
        kind.as_str(),
        "Pod" | "Deployment" | "DaemonSet" | "Binding" | "Role" | "RoleBinding"
    ) {
        crate::console::err(&format!(
            "Unsupported kind `{kind}`. Expected one of: Pod, Deployment, DaemonSet, Binding, Role, RoleBinding."
        ));
        return Ok(2);
    }

    let metadata_name = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .and_then(|meta| mapping_string(meta, "name"))
        .filter(|v| !v.is_empty());
    let metadata_name = match metadata_name {
        Some(v) => v,
        None => {
            crate::console::err("Manifest must include `metadata.name`.");
            return Ok(2);
        }
    };
    if !matches!(kind.as_str(), "Role" | "RoleBinding") && metadata_project(map).is_none() {
        crate::console::err("Manifest must include `metadata.project` for v1alpha1 resources.");
        return Ok(2);
    }

    if kind == "Role" {
        return apply_role_manifest(
            &yaml_content,
            map,
            args.validate_only || args.dry_run,
            args.base_url.as_deref(),
            args.json_out,
        );
    }
    if kind == "RoleBinding" {
        return apply_role_binding_manifest(
            &yaml_content,
            map,
            args.validate_only || args.dry_run,
            args.base_url.as_deref(),
            args.json_out,
        );
    }
    if kind == "Pod" {
        return apply_pod_manifest(
            &yaml_content,
            map,
            args.validate_only || args.dry_run,
            args.base_url.as_deref(),
            args.json_out,
        );
    }
    if kind == "Deployment" {
        return apply_deployment_manifest(
            &yaml_content,
            map,
            args.validate_only || args.dry_run,
            args.base_url.as_deref(),
            args.json_out,
        );
    }
    if kind == "Binding" {
        return apply_binding_manifest(
            map,
            args.validate_only || args.dry_run,
            args.base_url.as_deref(),
            args.json_out,
        );
    }
    if kind == "DaemonSet" {
        return apply_daemonset_manifest(
            map,
            args.validate_only || args.dry_run,
            args.base_url.as_deref(),
            args.json_out,
        );
    }

    if args.json_out {
        print_json(&json!({
            "ok": args.validate_only || args.dry_run,
            "apiVersion": api_version,
            "kind": kind,
            "name": metadata_name,
            "mode": if args.dry_run { "dry-run" } else if args.validate_only { "validate-only" } else { "apply" },
            "implemented": false,
            "message": if args.validate_only || args.dry_run {
                "Manifest envelope is valid; server-side apply for this kind is not implemented yet"
            } else {
                "This v1alpha1 resource kind is recognized, but server-side apply is not implemented yet"
            }
        }));
        return Ok(if args.validate_only || args.dry_run { 0 } else { 2 });
    }

    crate::console::ok(&format!(
        "Recognized {kind} manifest `{metadata_name}` ({api_version})."
    ));
    if args.validate_only || args.dry_run {
        crate::console::info(
            "Manifest envelope is valid. Server-side apply for this kind is not implemented yet.",
        );
        if args.dry_run {
            crate::console::info("Dry-run completed locally.");
        }
        Ok(0)
    } else {
        crate::console::warn("This v1alpha1 resource kind is not implemented yet.");
        Ok(2)
    }
}

pub fn reconcile_bindings(args: ReconcileBindingsArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);

    let node_id = match resolve_node_id_for_reconcile(&admin, args.node.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };

    let data = match if args.dry_run {
        admin.dry_run_bindings(
            node_id,
            Some(args.strategy.as_str()),
            Some(args.batch_size.max(1)),
            Some(args.max_unavailable.max(0)),
            Some(args.pause_seconds.max(0.0)),
        )
    } else {
        admin.reconcile_bindings_now(
            node_id,
            Some(args.strategy.as_str()),
            Some(args.batch_size.max(1)),
            Some(args.max_unavailable.max(0)),
            Some(args.pause_seconds.max(0.0)),
        )
    } {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "reconcile bindings"),
    };

    if args.json_out {
        print_json(&data);
    } else {
        crate::console::ok(&format!(
            "Bindings reconcile requested for node {}.",
            node_id
        ));
        if let Some(job_id) = data.get("job_id").and_then(|v| v.as_i64()) {
            crate::console::info(&format!("Job queued: {job_id}"));
        }
    }
    Ok(0)
}

pub fn describe_binding_drift(args: GetBindingDriftArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match resolve_node_id_for_reconcile(&admin, args.node.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let data = match admin.bindings_drift(node_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "describe binding drift"),
    };
    if args.json_out {
        print_json(&data);
    } else {
        crate::pretty_kv::print_value(&data);
    }
    Ok(0)
}

pub fn assign_deployments(args: AssignDeploymentArgs) -> io::Result<i32> {
    let deployment_names = match parse_service_codes(&args.deployments) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    if deployment_names.is_empty() {
        crate::console::err("Provide at least one --deployment value.");
        return Ok(2);
    }

    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match resolve_node_id_for_reconcile(&admin, args.node.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };

    let mut runtime_order = Vec::new();
    let mut runtime_specs = Vec::new();
    for deployment_name in &deployment_names {
        let deployment = match admin.get_deployment_by_name_raw(deployment_name) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "resolve deployment"),
        };
        let yaml_definition = deployment
            .get("yaml_definition")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if yaml_definition.is_empty() {
            crate::console::err("Deployment yaml_definition is missing in API response.");
            return Ok(2);
        }
        let runtime_ref = match deployment_yaml_pod_ref(yaml_definition) {
            Ok(v) => v,
            Err(e) => {
                crate::console::err(&e.to_string());
                return Ok(2);
            }
        };
        let replicas = deployment_yaml_replicas(yaml_definition).unwrap_or(1);
        let binding_name = format!("placement-{node_id}-{deployment_name}");
        let binding_meta = json!({
            "targetKind": "Deployment",
            "targetRef": deployment_name,
            "nodeRef": node_id.to_string(),
            "sourceCommand": "assign deployment",
        });
        match admin.get_binding_by_name_raw(&binding_name) {
            Ok(existing) => {
                let binding_id = existing.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
                if binding_id <= 0 {
                    crate::console::err("Invalid binding id in API response.");
                    return Ok(2);
                }
                if let Err(e) = admin.update_binding(
                    binding_id,
                    Some(node_id),
                    Some(deployment_name),
                    Some("placement"),
                    Some("active"),
                    Some(replicas),
                    Some("assign-deployment"),
                    Some(binding_meta.clone()),
                ) {
                    return fail_admin(e, "update placement binding");
                }
            }
            Err(e) if e.status_code == 404 => {
                if let Err(e) = admin.create_binding(
                    &binding_name,
                    node_id,
                    deployment_name,
                    "placement",
                    "active",
                    replicas,
                    Some("assign-deployment"),
                    Some(binding_meta.clone()),
                ) {
                    return fail_admin(e, "create placement binding");
                }
            }
            Err(e) => return fail_admin(e, "resolve placement binding"),
        }
        runtime_order.push(runtime_ref.clone());
        runtime_specs.push(DesiredServiceSpec {
            code: runtime_ref,
            replicas,
        });
    }

    let out = match set_desired_services(
        &admin,
        node_id,
        &runtime_order,
        runtime_specs,
        args.reconcile && !args.no_reconcile,
        &args.strategy,
        args.batch_size,
        args.max_unavailable,
        args.pause_seconds,
    ) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "set desired runtime refs"),
    };
    if args.json_out {
        print_json(&out);
    } else {
        crate::console::ok(&format!("Deployment bindings updated for node {node_id}."));
        print_desired_services(&out);
    }
    Ok(0)
}

pub fn unassign_deployments(args: UnassignDeploymentArgs) -> io::Result<i32> {
    if args.all && !args.deployments.is_empty() {
        crate::console::err("Use either --all or one/more --deployment flags.");
        return Ok(2);
    }
    if !args.all && args.deployments.is_empty() {
        crate::console::err("Provide --all or at least one --deployment value.");
        return Ok(2);
    }

    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let node_id = match resolve_node_id_for_reconcile(&admin, args.node.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };

    let existing_bindings = match admin.list_bindings_raw(Some("placement"), Some(node_id)) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list placement bindings"),
    };

    let (next_order, next_specs) = if args.all {
        for row in as_array(&existing_bindings) {
            if let Some(binding_id) = row.get("id").and_then(|v| v.as_i64()) {
                if let Err(e) = admin.delete_binding(binding_id) {
                    return fail_admin(e, "delete placement binding");
                }
            }
        }
        (Vec::new(), Vec::new())
    } else {
        let remove_codes = match parse_service_codes(&args.deployments) {
            Ok(v) => v,
            Err(msg) => {
                crate::console::err(&msg);
                return Ok(2);
            }
        };
        let remove_set: std::collections::HashSet<String> = remove_codes.iter().cloned().collect();
        for row in as_array(&existing_bindings) {
            let deployment_name = row
                .get("deployment_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if remove_set.contains(&deployment_name) {
                if let Some(binding_id) = row.get("id").and_then(|v| v.as_i64()) {
                    if let Err(e) = admin.delete_binding(binding_id) {
                        return fail_admin(e, "delete placement binding");
                    }
                }
            }
        }
        let current = match admin.get_bindings_runtime_raw(node_id) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "get desired services"),
        };
        let (order, replicas) = desired_replicas_map(&current);
        let next_order: Vec<String> = order
            .into_iter()
            .filter(|code| !remove_set.contains(code))
            .collect();
        let next_specs = desired_specs_from_order(&next_order, &replicas);
        (next_order, next_specs)
    };

    let out = match set_desired_services(
        &admin,
        node_id,
        &next_order,
        next_specs,
        args.reconcile && !args.no_reconcile,
        &args.strategy,
        args.batch_size,
        args.max_unavailable,
        args.pause_seconds,
    ) {
        Ok(v) => v,
        Err(e) => {
            return fail_admin(
                e,
                if args.all {
                    "clear deployment bindings"
                } else {
                    "remove deployment bindings"
                },
            )
        }
    };
    if args.json_out {
        print_json(&out);
    } else if args.all {
        crate::console::ok(&format!("Deployment bindings cleared for node {node_id}."));
        print_desired_services(&out);
    } else {
        crate::console::ok(&format!("Deployment bindings pruned for node {node_id}."));
        print_desired_services(&out);
    }
    Ok(0)
}

fn resolve_node_id_for_reconcile(
    admin: &AdminFacade<'_>,
    node_ref: Option<&str>,
) -> Result<i64, String> {
    if let Some(v) = node_ref {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return admin.resolve_node_id(trimmed);
        }
    }

    if !std::io::stdin().is_terminal() {
        return Err(
            "Node reference is required in non-interactive mode. Use --node <id|name>.".to_string(),
        );
    }

    let raw = admin
        .list_nodes_raw(None, Some(200), Some(0))
        .map_err(|e| e.message)?;
    let items = raw
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        return Err("No nodes found.".to_string());
    }

    let mut labels = Vec::new();
    let mut ids = Vec::new();
    for item in items {
        let id = item.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
        if id <= 0 {
            continue;
        }
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let host = item
            .get("public_host")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        labels.push(format!("{id}  {name}  ({host})"));
        ids.push(id);
    }
    if ids.is_empty() {
        return Err("No nodes with valid id found.".to_string());
    }

    let theme = ColorfulTheme::default();
    let idx = Select::with_theme(&theme)
        .with_prompt("Select node for reconcile")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())?;
    Ok(ids[idx])
}

fn mapping_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn metadata_project(map: &serde_yaml::Mapping) -> Option<String> {
    map.get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .and_then(|meta| mapping_string(meta, "project"))
}

fn metadata_workspace(map: &serde_yaml::Mapping) -> Option<String> {
    map.get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .and_then(|meta| mapping_string(meta, "workspace"))
}

fn metadata_display_name(map: &serde_yaml::Mapping, fallback: &str) -> String {
    let raw = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .and_then(|meta| {
            meta.get(serde_yaml::Value::String("annotations".to_string()))
                .and_then(|v| v.as_mapping())
        })
        .and_then(|annotations| mapping_string(annotations, "saharo.io/display-name"));
    raw.unwrap_or_else(|| fallback.to_string())
}

fn deployment_yaml_pod_ref(yaml_definition: &str) -> io::Result<String> {
    let parsed = serde_yaml::from_str::<serde_yaml::Value>(yaml_definition).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid deployment yaml_definition: {e}"),
        )
    })?;
    let map = parsed.as_mapping().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment yaml_definition must be a YAML object",
        )
    })?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deployment spec is required"))?;
    mapping_string(spec, "podRef").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment yaml_definition must include spec.podRef",
        )
    })
}

fn deployment_yaml_replicas(yaml_definition: &str) -> io::Result<i64> {
    let parsed = serde_yaml::from_str::<serde_yaml::Value>(yaml_definition).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid deployment yaml_definition: {e}"),
        )
    })?;
    let map = parsed.as_mapping().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment yaml_definition must be a YAML object",
        )
    })?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deployment spec is required"))?;
    Ok(
        spec.get(serde_yaml::Value::String("replicas".to_string()))
            .and_then(yaml_i64)
            .unwrap_or(1)
            .max(1),
    )
}

const CANONICAL_ROLE_RESOURCES: &[&str] = &[
    "audit",
    "bindings",
    "daemonsets",
    "deployments",
    "host",
    "invites",
    "jobs",
    "nodes",
    "pods",
    "rolebindings",
    "roles",
    "users",
    "*",
];

const CANONICAL_ROLE_VERBS: &[&str] = &[
    "apply",
    "assign",
    "create",
    "delete",
    "get",
    "list",
    "reconcile",
    "update",
    "watch",
    "*",
];

fn is_valid_role_resource(resource: &str) -> bool {
    CANONICAL_ROLE_RESOURCES.contains(&resource)
}

fn is_valid_role_verb(verb: &str) -> bool {
    CANONICAL_ROLE_VERBS.contains(&verb)
}

fn apply_role_manifest(
    yaml_content: &str,
    map: &serde_yaml::Mapping,
    validate_only: bool,
    base_url: Option<&str>,
    json_out: bool,
) -> io::Result<i32> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Role must include `metadata`."))?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Role must include `spec`."))?;

    let name = mapping_string(metadata, "name").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Role must include `metadata.name`.")
    })?;
    let rules = spec
        .get(serde_yaml::Value::String("rules".to_string()))
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Role must include `spec.rules`."))?;
    if rules.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Role must include at least one rule in `spec.rules`.",
        ));
    }
    for (idx, rule) in rules.iter().enumerate() {
        let rule_map = rule.as_mapping().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must be an object.", idx + 1),
            )
        })?;
        let effect = mapping_string(rule_map, "effect").unwrap_or_default().to_lowercase();
        if !matches!(effect.as_str(), "allow" | "deny") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must include `effect: allow|deny`.", idx + 1),
            ));
        }
        let resources = rule_map
            .get(serde_yaml::Value::String("resources".to_string()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|item| item.as_str())
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if resources.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must include at least one resource.", idx + 1),
            ));
        }
        let invalid_resources = resources
            .iter()
            .map(|item| item.to_lowercase())
            .filter(|item| !is_valid_role_resource(item))
            .collect::<Vec<_>>();
        if !invalid_resources.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Role rule #{} contains unsupported resources: {}.",
                    idx + 1,
                    invalid_resources.join(", ")
                ),
            ));
        }
        let verbs = rule_map
            .get(serde_yaml::Value::String("verbs".to_string()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|item| item.as_str())
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if verbs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must include at least one verb.", idx + 1),
            ));
        }
        let invalid_verbs = verbs
            .iter()
            .map(|item| item.to_lowercase())
            .filter(|item| !is_valid_role_verb(item))
            .collect::<Vec<_>>();
        if !invalid_verbs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Role rule #{} contains unsupported verbs: {}.",
                    idx + 1,
                    invalid_verbs.join(", ")
                ),
            ));
        }
        let scope = rule_map
            .get(serde_yaml::Value::String("scope".to_string()))
            .and_then(|v| v.as_mapping())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Role rule #{} must include `scope`.", idx + 1),
                )
            })?;
        let scope_type = mapping_string(scope, "type").unwrap_or_default().to_lowercase();
        if !matches!(scope_type.as_str(), "global" | "workspace" | "project" | "object") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} has unsupported scope type `{scope_type}`.", idx + 1),
            ));
        }
        if matches!(scope_type.as_str(), "workspace" | "project" | "object")
            && mapping_string(scope, "workspace").is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must include `scope.workspace`.", idx + 1),
            ));
        }
        if matches!(scope_type.as_str(), "project" | "object")
            && mapping_string(scope, "project").is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must include `scope.project`.", idx + 1),
            ));
        }
        if scope_type == "object"
            && (mapping_string(scope, "kind").is_none() || mapping_string(scope, "name").is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Role rule #{} must include `scope.kind` and `scope.name`.", idx + 1),
            ));
        }
    }

    if validate_only {
        if json_out {
            print_json(&json!({
                "ok": true,
                "kind": "Role",
                "name": name,
                "ruleCount": rules.len(),
                "mode": "validate-only",
            }));
        } else {
            crate::console::ok("Role manifest is valid.");
            crate::console::info(&format!("Role: {name}"));
            crate::console::info(&format!("Rules: {}", rules.len()));
        }
        return Ok(0);
    }

    let client = client_from_base(base_url)?;
    let admin = AdminFacade::new(&client);
    let existing = match admin.get_role_by_name_raw(&name) {
        Ok(v) => Some(v),
        Err(e) if e.status_code == 404 => None,
        Err(e) => return fail_admin(e, "resolve role by name"),
    };

    let (action, role) = if let Some(existing_raw) = existing {
        let role_id = existing_raw
            .get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid role id in response"))?;
        let updated = admin
            .update_role(role_id, Some(yaml_content))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format_admin_error(&e, "apply role")))?;
        ("updated", updated)
    } else {
        let created = admin
            .create_role(&name, yaml_content)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format_admin_error(&e, "create role")))?;
        ("created", created)
    };

    if json_out {
        print_json(&json!({
            "action": action,
            "role": role,
        }));
    } else {
        let role_id = role.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
        crate::console::ok(&format!("Role '{name}' {action} (id={role_id})."));
    }
    Ok(0)
}

fn apply_role_binding_manifest(
    yaml_content: &str,
    map: &serde_yaml::Mapping,
    validate_only: bool,
    base_url: Option<&str>,
    json_out: bool,
) -> io::Result<i32> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `metadata`."))?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `spec`."))?;
    let name = mapping_string(metadata, "name").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `metadata.name`.")
    })?;
    let subject = spec
        .get(serde_yaml::Value::String("subject".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `spec.subject`."))?;
    let subject_kind = mapping_string(subject, "kind").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `spec.subject.kind`.")
    })?;
    if subject_kind != "User" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RoleBinding currently supports only `spec.subject.kind: User`.",
        ));
    }
    let subject_name = mapping_string(subject, "name");
    let subject_id = subject
        .get(serde_yaml::Value::String("id".to_string()))
        .and_then(yaml_i64);
    if subject_name.is_none() && subject_id.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RoleBinding must include `spec.subject.name` or `spec.subject.id`.",
        ));
    }
    let role_ref = spec
        .get(serde_yaml::Value::String("roleRef".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `spec.roleRef`."))?;
    let role_name = mapping_string(role_ref, "name").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "RoleBinding must include `spec.roleRef.name`.")
    })?;

    if validate_only {
        if json_out {
            print_json(&json!({
                "ok": true,
                "kind": "RoleBinding",
                "name": name,
                "subjectKind": subject_kind,
                "subjectName": subject_name,
                "subjectId": subject_id,
                "roleRef": role_name,
                "mode": "validate-only",
            }));
        } else {
            crate::console::ok("RoleBinding manifest is valid.");
            crate::console::info(&format!("RoleBinding: {name}"));
            crate::console::info(&format!("Role ref: {role_name}"));
        }
        return Ok(0);
    }

    let client = client_from_base(base_url)?;
    let admin = AdminFacade::new(&client);
    let existing = match admin.get_role_binding_by_name_raw(&name) {
        Ok(v) => Some(v),
        Err(e) if e.status_code == 404 => None,
        Err(e) => return fail_admin(e, "resolve role binding by name"),
    };

    let (action, binding) = if let Some(existing_raw) = existing {
        let binding_id = existing_raw
            .get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid role binding id in response"))?;
        let updated = admin
            .update_role_binding(binding_id, Some(yaml_content))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format_admin_error(&e, "apply role binding")))?;
        ("updated", updated)
    } else {
        let created = admin
            .create_role_binding(&name, yaml_content)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format_admin_error(&e, "create role binding")))?;
        ("created", created)
    };

    if json_out {
        print_json(&json!({
            "action": action,
            "roleBinding": binding,
        }));
    } else {
        let binding_id = binding.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
        crate::console::ok(&format!("RoleBinding '{name}' {action} (id={binding_id})."));
    }
    Ok(0)
}

fn apply_deployment_manifest(
    yaml_content: &str,
    map: &serde_yaml::Mapping,
    validate_only: bool,
    base_url: Option<&str>,
    json_out: bool,
) -> io::Result<i32> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Deployment must include `metadata`.",
            )
        })?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Deployment must include `spec`.",
            )
        })?;

    let name = mapping_string(metadata, "name").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment must include `metadata.name`.",
        )
    })?;
    let project = mapping_string(metadata, "project").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment must include `metadata.project`.",
        )
    })?;
    let pod_ref = mapping_string(spec, "podRef").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment must include non-empty `spec.podRef`.",
        )
    })?;
    let replicas = spec
        .get(serde_yaml::Value::String("replicas".to_string()))
        .and_then(yaml_i64)
        .unwrap_or(1);
    if replicas < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment `spec.replicas` must be >= 0.",
        ));
    }
    let node_ref = deployment_node_ref(spec).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment apply currently requires a target node. Use `spec.nodeRef`, `spec.targetNode`, `spec.placement.nodeRef`, or `spec.placement.nodeSelector.nodeRef` until scheduler support exists.",
        )
    })?;
    let rollout = deployment_rollout(spec)?;
    let workspace = metadata_workspace(map);
    let display_name = metadata_display_name(map, &name);

    if validate_only {
        if json_out {
            print_json(&json!({
                "ok": true,
                "kind": "Deployment",
                "name": name,
                "displayName": display_name,
                "workspace": workspace,
                "project": project,
                "podRef": pod_ref,
                "nodeRef": node_ref,
                "replicas": replicas,
                "mode": "validate-only"
            }));
        } else {
            crate::console::ok("Deployment manifest is valid.");
            crate::console::info(&format!("Deployment: {name}"));
            crate::console::info(&format!("Display name: {display_name}"));
            if let Some(workspace) = &workspace {
                crate::console::info(&format!("Workspace: {workspace}"));
            }
            crate::console::info(&format!("Project: {project}"));
            crate::console::info(&format!("Pod ref: {pod_ref}"));
            crate::console::info(&format!("Target node: {node_ref}"));
            crate::console::info(&format!("Replicas: {replicas}"));
        }
        return Ok(0);
    }

    let client = client_from_base(base_url)?;
    let admin = AdminFacade::new(&client);
    let deployment = match admin.get_deployment_by_name_raw(&name) {
        Ok(existing) => {
            let deployment_id = existing.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
            if deployment_id <= 0 {
                crate::console::err("Invalid deployment id in API response.");
                return Ok(2);
            }
            match admin.update_deployment(
                deployment_id,
                Some(&display_name),
                Some(yaml_content),
                workspace.as_deref(),
                Some(&project),
                Some(true),
            ) {
                Ok(v) => v,
                Err(e) => return fail_admin(e, "update deployment"),
            }
        }
        Err(e) if e.status_code == 404 => match admin.create_deployment(
            &name,
            &display_name,
            yaml_content,
            workspace.as_deref(),
            Some(&project),
            true,
        ) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "create deployment"),
        },
        Err(e) => return fail_admin(e, "resolve deployment"),
    };
    let node_id = match admin.resolve_node_id(&node_ref) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let out = match merge_desired_service_for_node(
        &admin,
        node_id,
        &pod_ref,
        replicas,
        true,
        &rollout.strategy,
        rollout.batch_size,
        rollout.max_unavailable,
        rollout.pause_seconds,
    ) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "apply deployment"),
    };

    if json_out {
        print_json(&json!({
            "action": "applied",
            "kind": "Deployment",
            "name": name,
            "deployment": deployment,
            "displayName": display_name,
            "workspace": workspace,
            "project": project,
            "podRef": pod_ref,
            "nodeRef": node_ref,
            "nodeId": node_id,
            "replicas": replicas,
            "result": out,
        }));
    } else {
        crate::console::ok(&format!(
            "Deployment '{name}' applied to node {node_id} for pod '{pod_ref}'."
        ));
        crate::console::info(&format!("Display name: {display_name}"));
        if let Some(workspace) = &workspace {
            crate::console::info(&format!("Workspace: {workspace}"));
        }
        crate::console::info(&format!("Project: {project}"));
        print_desired_services(&out);
    }
    Ok(0)
}

fn apply_binding_manifest(
    map: &serde_yaml::Mapping,
    validate_only: bool,
    base_url: Option<&str>,
    json_out: bool,
) -> io::Result<i32> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Binding must include `metadata`.")
        })?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Binding must include `spec`.")
        })?;

    let name = mapping_string(metadata, "name").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Binding must include `metadata.name`.",
        )
    })?;
    let project = mapping_string(metadata, "project").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Binding must include `metadata.project`.",
        )
    })?;
    let target_kind = mapping_string(spec, "targetKind").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Binding must include non-empty `spec.targetKind`.",
        )
    })?;
    let target_ref = mapping_string(spec, "targetRef").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Binding must include non-empty `spec.targetRef`.",
        )
    })?;
    let node_ref = mapping_string(spec, "nodeRef").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Binding must include non-empty `spec.nodeRef`.",
        )
    })?;
    let mode = mapping_string(spec, "mode").unwrap_or_else(|| "Pinned".to_string());
    let workspace = metadata_workspace(map);
    if !matches!(target_kind.as_str(), "Deployment" | "Pod") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported Binding targetKind `{target_kind}`. Expected Deployment or Pod."),
        ));
    }
    if mode != "Pinned" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Binding mode `{mode}` is not supported yet. Only `Pinned` is currently implemented."
            ),
        ));
    }

    if validate_only {
        if json_out {
            print_json(&json!({
                "ok": true,
                "kind": "Binding",
                "name": name,
                "workspace": workspace,
                "project": project,
                "targetKind": target_kind,
                "targetRef": target_ref,
                "nodeRef": node_ref,
                "mode": mode,
            }));
        } else {
            crate::console::ok("Binding manifest is valid.");
            crate::console::info(&format!("Binding: {name}"));
            if let Some(workspace) = &workspace {
                crate::console::info(&format!("Workspace: {workspace}"));
            }
            crate::console::info(&format!("Project: {project}"));
            crate::console::info(&format!("Target: {target_kind}/{target_ref}"));
            crate::console::info(&format!("Node: {node_ref}"));
            crate::console::info(&format!("Mode: {mode}"));
        }
        return Ok(0);
    }

    let client = client_from_base(base_url)?;
    let admin = AdminFacade::new(&client);
    let node_id = match admin.resolve_node_id(&node_ref) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let deployment_name = target_ref.to_lowercase();
    let binding_meta = json!({
        "project": project,
        "workspace": workspace,
        "targetKind": target_kind,
        "targetRef": target_ref,
        "mode": mode,
        "nodeRef": node_ref,
    });
    let binding = match admin.get_binding_by_name_raw(&name) {
        Ok(existing) => {
            let binding_id = existing.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
            if binding_id <= 0 {
                crate::console::err("Invalid binding id in API response.");
                return Ok(2);
            }
            match admin.update_binding(
                binding_id,
                Some(node_id),
                Some(&deployment_name),
                Some("placement"),
                Some("active"),
                Some(1),
                Some("binding-manifest"),
                Some(binding_meta.clone()),
            ) {
                Ok(v) => v,
                Err(e) => return fail_admin(e, "update binding"),
            }
        }
        Err(e) if e.status_code == 404 => match admin.create_binding(
            &name,
            node_id,
            &deployment_name,
            "placement",
            "active",
            1,
            Some("binding-manifest"),
            Some(binding_meta.clone()),
        ) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "create binding"),
        },
        Err(e) => return fail_admin(e, "resolve binding"),
    };
    let runtime_ref = if target_kind == "Deployment" {
        let deployment = match admin.get_deployment_by_name_raw(&deployment_name) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "resolve deployment for binding"),
        };
        let yaml_definition = deployment
            .get("yaml_definition")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if yaml_definition.is_empty() {
            crate::console::err("Deployment yaml_definition is missing in API response.");
            return Ok(2);
        }
        match deployment_yaml_pod_ref(yaml_definition) {
            Ok(v) => v,
            Err(e) => {
                crate::console::err(&e.to_string());
                return Ok(2);
            }
        }
    } else {
        target_ref.clone()
    };
    let current = match admin.get_bindings_runtime_raw(node_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get desired services"),
    };
    let (_, replicas_map) = desired_replicas_map(&current);
    let replicas = replicas_map.get(&runtime_ref).copied().unwrap_or(1);
    let out = match merge_desired_service_for_node(
        &admin,
        node_id,
        &runtime_ref,
        replicas,
        true,
        "safe",
        1,
        1,
        0.0,
    ) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "apply binding"),
    };

    if json_out {
        print_json(&json!({
            "action": "applied",
            "kind": "Binding",
            "name": name,
            "binding": binding,
            "workspace": workspace,
            "project": project,
            "targetKind": target_kind,
            "targetRef": target_ref,
            "runtimeRef": runtime_ref,
            "nodeRef": node_ref,
            "nodeId": node_id,
            "mode": mode,
            "result": out,
        }));
    } else {
        crate::console::ok(&format!(
            "Binding '{name}' pinned {target_kind} '{target_ref}' to node {node_id}."
        ));
        if let Some(workspace) = &workspace {
            crate::console::info(&format!("Workspace: {workspace}"));
        }
        crate::console::info(&format!("Project: {project}"));
        crate::console::info(&format!("Runtime ref: {runtime_ref}"));
        print_desired_services(&out);
    }

    Ok(0)
}

fn apply_daemonset_manifest(
    map: &serde_yaml::Mapping,
    validate_only: bool,
    base_url: Option<&str>,
    json_out: bool,
) -> io::Result<i32> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DaemonSet must include `metadata`.",
            )
        })?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "DaemonSet must include `spec`.")
        })?;

    let name = mapping_string(metadata, "name").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DaemonSet must include `metadata.name`.",
        )
    })?;
    let project = mapping_string(metadata, "project").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DaemonSet must include `metadata.project`.",
        )
    })?;
    let pod_ref = mapping_string(spec, "podRef").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DaemonSet must include non-empty `spec.podRef`.",
        )
    })?;
    let selector = daemonset_selector(spec)?;

    let client = client_from_base(base_url)?;
    let admin = AdminFacade::new(&client);
    let raw = admin
        .list_nodes_raw(None, Some(500), Some(0))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format_admin_error(&e, "list nodes")))?;
    let nodes = raw
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let matched: Vec<Value> = nodes
        .into_iter()
        .filter(|node| daemonset_matches_node(node, &selector))
        .collect();

    if validate_only {
        let matched_names: Vec<String> = matched.iter().filter_map(node_name).collect();
        if json_out {
            print_json(&json!({
                "ok": true,
                "kind": "DaemonSet",
                "name": name,
                "project": project,
                "podRef": pod_ref,
                "matchedNodes": matched_names,
                "matchedCount": matched_names.len(),
            }));
        } else {
            crate::console::ok("DaemonSet manifest is valid.");
            crate::console::info(&format!("DaemonSet: {name}"));
            crate::console::info(&format!("Project: {project}"));
            crate::console::info(&format!("Pod ref: {pod_ref}"));
            crate::console::info(&format!("Matched nodes: {}", matched_names.len()));
            if !matched_names.is_empty() {
                crate::console::info(&format!("Nodes: {}", matched_names.join(", ")));
            }
        }
        return Ok(0);
    }

    let mut applied = Vec::new();
    for node in matched {
        let node_id = match node.get("id").and_then(|v| v.as_i64()) {
            Some(v) if v > 0 => v,
            _ => continue,
        };
        let node_name = node_name(&node).unwrap_or_else(|| node_id.to_string());
        let out = match merge_desired_service_for_node(
            &admin, node_id, &pod_ref, 1, true, "safe", 1, 1, 0.0,
        ) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, &format!("apply daemonset to node {node_name}")),
        };
        applied.push(json!({
            "nodeId": node_id,
            "nodeName": node_name,
            "result": out,
        }));
    }

    if json_out {
        print_json(&json!({
            "action": "applied",
            "kind": "DaemonSet",
            "name": name,
            "project": project,
            "podRef": pod_ref,
            "matchedCount": applied.len(),
            "appliedNodes": applied,
        }));
    } else if applied.is_empty() {
        crate::console::warn(&format!(
            "DaemonSet '{name}' matched no nodes. Nothing was applied."
        ));
        crate::console::info(&format!("Project: {project}"));
    } else {
        crate::console::ok(&format!(
            "DaemonSet '{name}' applied to {} node(s).",
            applied.len()
        ));
        crate::console::info(&format!("Project: {project}"));
    }
    Ok(0)
}

fn pod_manifest_to_service_yaml(map: &serde_yaml::Mapping) -> io::Result<String> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Pod must include `metadata`."))?;
    let spec = map
        .get(serde_yaml::Value::String("spec".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Pod must include `spec`."))?;

    let name = mapping_string(metadata, "name")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Pod must include `metadata.name`."))?;
    let display_name = metadata
        .get(serde_yaml::Value::String("annotations".to_string()))
        .and_then(|v| v.as_mapping())
        .and_then(|ann| mapping_string(ann, "saharo.io/display-name"))
        .unwrap_or_else(|| name.clone());

    let containers = spec
        .get(serde_yaml::Value::String("containers".to_string()))
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Pod spec must include non-empty `containers`.",
            )
        })?;
    let first_container = containers.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pod spec must include at least one container.",
        )
    })?;
    let container_map = first_container.as_mapping().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pod container entry must be an object.",
        )
    })?;

    let mut legacy = serde_yaml::Mapping::new();
    legacy.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String(name),
    );
    legacy.insert(
        serde_yaml::Value::String("display_name".to_string()),
        serde_yaml::Value::String(display_name),
    );
    if let Some(project) = mapping_string(metadata, "project") {
        let mut legacy_metadata = serde_yaml::Mapping::new();
        legacy_metadata.insert(
            serde_yaml::Value::String("project".to_string()),
            serde_yaml::Value::String(project),
        );
        legacy.insert(
            serde_yaml::Value::String("metadata".to_string()),
            serde_yaml::Value::Mapping(legacy_metadata),
        );
    }
    legacy.insert(
        serde_yaml::Value::String("container".to_string()),
        serde_yaml::Value::Mapping(container_map.clone()),
    );

    copy_spec_mapping(spec, &mut legacy, "health");
    copy_spec_mapping(spec, &mut legacy, "bootstrap");
    copy_spec_mapping(spec, &mut legacy, "lifecycle");

    if let Some(rollout) = spec.get(serde_yaml::Value::String("rolloutDefaults".to_string())) {
        legacy.insert(
            serde_yaml::Value::String("rollout".to_string()),
            rollout.clone(),
        );
    }
    if let Some(restart_policy) =
        spec.get(serde_yaml::Value::String("restartPolicy".to_string()))
    {
        let container = legacy
            .get_mut(serde_yaml::Value::String("container".to_string()))
            .and_then(|v| v.as_mapping_mut())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid generated container spec")
            })?;
        container.insert(
            serde_yaml::Value::String("restart_policy".to_string()),
            normalize_restart_policy(restart_policy.clone()),
        );
    }

    serde_yaml::to_string(&serde_yaml::Value::Mapping(legacy))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid Pod manifest: {e}")))
}

fn apply_pod_manifest(
    yaml_content: &str,
    map: &serde_yaml::Mapping,
    validate_only: bool,
    base_url: Option<&str>,
    json_out: bool,
) -> io::Result<i32> {
    let metadata = map
        .get(serde_yaml::Value::String("metadata".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Pod must include `metadata`."))?;
    let name = mapping_string(metadata, "name")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Pod must include `metadata.name`."))?;
    let project = mapping_string(metadata, "project")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Pod must include `metadata.project`."))?;
    let workspace = mapping_string(metadata, "workspace");
    let display_name = metadata_display_name(map, &name);

    let _ = pod_manifest_to_service_yaml(map)?;

    if validate_only {
        if json_out {
            print_json(&json!({
                "ok": true,
                "kind": "Pod",
                "name": name,
                "displayName": display_name,
                "workspace": workspace,
                "project": project,
                "mode": "validate-only"
            }));
        } else {
            crate::console::ok("Pod manifest is valid.");
            crate::console::info(&format!("Pod: {name}"));
            crate::console::info(&format!("Display name: {display_name}"));
            if let Some(workspace) = &workspace {
                crate::console::info(&format!("Workspace: {workspace}"));
            }
            crate::console::info(&format!("Project: {project}"));
        }
        return Ok(0);
    }

    let client = client_from_base(base_url)?;
    let admin = AdminFacade::new(&client);
    let pod = match admin.get_pod_by_name_raw(&name) {
        Ok(existing) => {
            let pod_id = existing.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
            if pod_id <= 0 {
                crate::console::err("Invalid pod id in API response.");
                return Ok(2);
            }
            match admin.update_pod(
                pod_id,
                Some(&display_name),
                Some(yaml_content),
                workspace.as_deref(),
                Some(&project),
            ) {
                Ok(v) => v,
                Err(e) => return fail_admin(e, "update pod"),
            }
        }
        Err(e) if e.status_code == 404 => match admin.create_pod(
            &name,
            &display_name,
            yaml_content,
            workspace.as_deref(),
            Some(&project),
        ) {
            Ok(v) => v,
            Err(e) => return fail_admin(e, "create pod"),
        },
        Err(e) => return fail_admin(e, "resolve pod"),
    };

    if json_out {
        print_json(&json!({
            "action": "applied",
            "kind": "Pod",
            "name": name,
            "displayName": display_name,
            "workspace": workspace,
            "project": project,
            "pod": pod,
        }));
    } else {
        let pod_id = pod.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
        crate::console::ok(&format!("Pod '{name}' applied (id={pod_id})."));
        crate::console::info(&format!("Display name: {display_name}"));
        if let Some(workspace) = &workspace {
            crate::console::info(&format!("Workspace: {workspace}"));
        }
        crate::console::info(&format!("Project: {project}"));
    }
    Ok(0)
}

fn copy_spec_mapping(spec: &serde_yaml::Mapping, out: &mut serde_yaml::Mapping, key: &str) {
    if let Some(value) = spec.get(serde_yaml::Value::String(key.to_string())) {
        out.insert(serde_yaml::Value::String(key.to_string()), value.clone());
    }
}

fn normalize_restart_policy(value: serde_yaml::Value) -> serde_yaml::Value {
    match value {
        serde_yaml::Value::String(s) => {
            let normalized = match s.trim() {
                "Always" => "always",
                "UnlessStopped" => "unless-stopped",
                "OnFailure" => "on-failure",
                "Never" => "no",
                other => other,
            };
            serde_yaml::Value::String(normalized.to_string())
        }
        other => other,
    }
}

struct DeploymentRollout {
    strategy: String,
    batch_size: i64,
    max_unavailable: i64,
    pause_seconds: f64,
}

#[derive(Default)]
struct DaemonSetSelector {
    node_ref: Option<String>,
    name: Option<String>,
    host: Option<String>,
    region: Option<String>,
    country: Option<String>,
    enabled: Option<bool>,
    maintenance: Option<bool>,
    allow_nodes: Vec<String>,
    deny_nodes: Vec<String>,
}

fn deployment_node_ref(spec: &serde_yaml::Mapping) -> Option<String> {
    mapping_string(spec, "nodeRef")
        .or_else(|| mapping_string(spec, "targetNode"))
        .or_else(|| {
            spec.get(serde_yaml::Value::String("placement".to_string()))
                .and_then(|v| v.as_mapping())
                .and_then(|placement| {
                    mapping_string(placement, "nodeRef").or_else(|| {
                        placement
                            .get(serde_yaml::Value::String("nodeSelector".to_string()))
                            .and_then(|v| v.as_mapping())
                            .and_then(|selector| mapping_string(selector, "nodeRef"))
                    })
                })
        })
}

fn deployment_rollout(spec: &serde_yaml::Mapping) -> io::Result<DeploymentRollout> {
    let strategy = spec
        .get(serde_yaml::Value::String("strategy".to_string()))
        .and_then(|v| v.as_mapping());
    let strategy_type = strategy
        .and_then(|v| mapping_string(v, "type"))
        .unwrap_or_else(|| "RollingUpdate".to_string());
    let rollout_strategy = match strategy_type.as_str() {
        "RollingUpdate" => "rolling",
        "Recreate" => "recreate",
        "Safe" => "safe",
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Unsupported deployment strategy `{other}`. Expected RollingUpdate, Recreate, or Safe."
                ),
            ))
        }
    };
    let batch_size = strategy
        .and_then(|v| v.get(serde_yaml::Value::String("batchSize".to_string())))
        .and_then(yaml_i64)
        .unwrap_or(1);
    let max_unavailable = strategy
        .and_then(|v| v.get(serde_yaml::Value::String("maxUnavailable".to_string())))
        .and_then(yaml_i64)
        .unwrap_or(1);
    let pause_seconds = strategy
        .and_then(|v| v.get(serde_yaml::Value::String("pauseSeconds".to_string())))
        .and_then(yaml_f64)
        .unwrap_or(0.0);

    if batch_size < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment `spec.strategy.batchSize` must be >= 1.",
        ));
    }
    if max_unavailable < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment `spec.strategy.maxUnavailable` must be >= 0.",
        ));
    }
    if pause_seconds < 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Deployment `spec.strategy.pauseSeconds` must be >= 0.",
        ));
    }

    Ok(DeploymentRollout {
        strategy: rollout_strategy.to_string(),
        batch_size,
        max_unavailable,
        pause_seconds,
    })
}

fn daemonset_selector(spec: &serde_yaml::Mapping) -> io::Result<DaemonSetSelector> {
    let mut selector = DaemonSetSelector::default();
    let placement = spec
        .get(serde_yaml::Value::String("placement".to_string()))
        .and_then(|v| v.as_mapping());
    if let Some(placement) = placement {
        selector.node_ref = mapping_string(placement, "nodeRef");
        selector.allow_nodes = mapping_string_list(placement, "allowNodes");
        selector.deny_nodes = mapping_string_list(placement, "denyNodes");
        if let Some(node_selector) = placement
            .get(serde_yaml::Value::String("nodeSelector".to_string()))
            .and_then(|v| v.as_mapping())
        {
            for (key, value) in node_selector {
                let Some(key) = key.as_str() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "DaemonSet nodeSelector keys must be strings.",
                    ));
                };
                match key {
                    "nodeRef" => selector.node_ref = yaml_string(value),
                    "name" => selector.name = yaml_string(value),
                    "host" | "publicHost" | "public_host" => selector.host = yaml_string(value),
                    "region" | "regionCode" | "region_code" => selector.region = yaml_string(value),
                    "country" | "countryCode" | "country_code" => {
                        selector.country = yaml_string(value)
                    }
                    "enabled" => selector.enabled = yaml_bool(value),
                    "maintenance" => selector.maintenance = yaml_bool(value),
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Unsupported DaemonSet nodeSelector key `{other}`. Supported keys: nodeRef, name, host, publicHost, region, country, enabled, maintenance."
                            ),
                        ))
                    }
                }
            }
        }
    }
    Ok(selector)
}

fn yaml_i64(value: &serde_yaml::Value) -> Option<i64> {
    value.as_i64()
}

fn yaml_f64(value: &serde_yaml::Value) -> Option<f64> {
    value.as_f64().or_else(|| value.as_i64().map(|v| v as f64))
}

fn yaml_string(value: &serde_yaml::Value) -> Option<String> {
    value
        .as_str()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn yaml_bool(value: &serde_yaml::Value) -> Option<bool> {
    if let Some(v) = value.as_bool() {
        return Some(v);
    }
    value.as_str().and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn mapping_string_list(map: &serde_yaml::Mapping, key: &str) -> Vec<String> {
    map.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_sequence())
        .into_iter()
        .flatten()
        .filter_map(yaml_string)
        .collect()
}

fn daemonset_matches_node(node: &Value, selector: &DaemonSetSelector) -> bool {
    let name = node_name(node).unwrap_or_default();
    let host = node
        .get("public_host")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let region = node
        .get("region_code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let country = node
        .get("country_code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if let Some(ref want) = selector.node_ref {
        let node_id = node.get("id").and_then(|v| v.as_i64()).map(|v| v.to_string());
        if name != *want && host != *want && node_id.as_deref() != Some(want.as_str()) {
            return false;
        }
    }
    if let Some(ref want) = selector.name {
        if name != *want {
            return false;
        }
    }
    if let Some(ref want) = selector.host {
        if host != *want {
            return false;
        }
    }
    if let Some(ref want) = selector.region {
        if region != *want {
            return false;
        }
    }
    if let Some(ref want) = selector.country {
        if country != *want {
            return false;
        }
    }
    if let Some(want) = selector.enabled {
        if node.get("enabled").and_then(|v| v.as_bool()) != Some(want) {
            return false;
        }
    }
    if let Some(want) = selector.maintenance {
        if node.get("maintenance").and_then(|v| v.as_bool()) != Some(want) {
            return false;
        }
    }
    if !selector.allow_nodes.is_empty()
        && !selector.allow_nodes.iter().any(|item| item == &name || item == &host)
    {
        return false;
    }
    if selector.deny_nodes.iter().any(|item| item == &name || item == &host) {
        return false;
    }
    true
}

fn node_name(node: &Value) -> Option<String> {
    node.get("name")
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn merge_desired_service_for_node(
    admin: &AdminFacade<'_>,
    node_id: i64,
    service_code: &str,
    replicas: i64,
    enqueue_reconcile: bool,
    strategy: &str,
    batch_size: i64,
    max_unavailable: i64,
    pause_seconds: f64,
) -> Result<Value, ApiError> {
    let current = admin.get_bindings_runtime_raw(node_id)?;
    let (mut order, mut replicas_map) = desired_replicas_map(&current);
    if replicas == 0 {
        order.retain(|code| code != service_code);
        replicas_map.remove(service_code);
    } else {
        if !order.iter().any(|code| code == service_code) {
            order.push(service_code.to_string());
        }
        replicas_map.insert(service_code.to_string(), replicas);
    }
    let specs = desired_specs_from_order(&order, &replicas_map);
    set_desired_services(
        admin,
        node_id,
        &order,
        specs,
        enqueue_reconcile,
        strategy,
        batch_size,
        max_unavailable,
        pause_seconds,
    )
}

#[derive(Clone, Debug)]
struct DesiredServiceSpec {
    code: String,
    replicas: i64,
}

fn parse_service_codes(values: &[String]) -> Result<Vec<String>, String> {
    let mut codes = Vec::new();
    for raw in values {
        for part in raw.split(',') {
            let code = part.trim().to_lowercase();
            if code.is_empty() {
                continue;
            }
            if code.contains('=') || code.contains(':') {
                return Err(format!(
                    "Invalid identifier '{part}'. Use plain deployment names without replica syntax."
                ));
            }
            if !codes.contains(&code) {
                codes.push(code);
            }
        }
    }
    Ok(codes)
}

fn desired_replicas_map(state: &Value) -> (Vec<String>, std::collections::HashMap<String, i64>) {
    let desired_raw = state
        .get("desired_services")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let replicas_raw = state
        .get("desired_service_replicas")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let mut order = Vec::new();
    let mut replicas = std::collections::HashMap::new();
    for item in desired_raw {
        if let Some(code) = item.as_str().map(|v| v.trim().to_lowercase()) {
            if code.is_empty() {
                continue;
            }
            if !order.contains(&code) {
                order.push(code.clone());
            }
            let rep = replicas_raw
                .get(&code)
                .and_then(|v| v.as_i64())
                .unwrap_or(1)
                .max(1);
            replicas.insert(code, rep);
        }
    }
    for (code, value) in replicas_raw {
        let code = code.trim().to_lowercase();
        if code.is_empty() {
            continue;
        }
        if !order.contains(&code) {
            order.push(code.clone());
        }
        replicas.insert(code, value.as_i64().unwrap_or(1).max(1));
    }
    (order, replicas)
}

fn desired_specs_from_order(
    order: &[String],
    replicas: &std::collections::HashMap<String, i64>,
) -> Vec<DesiredServiceSpec> {
    order.iter()
        .map(|code| DesiredServiceSpec {
            code: code.clone(),
            replicas: replicas.get(code).copied().unwrap_or(1).max(1),
        })
        .collect()
}

fn set_desired_services(
    admin: &AdminFacade<'_>,
    node_id: i64,
    order: &[String],
    specs: Vec<DesiredServiceSpec>,
    reconcile: bool,
    strategy: &str,
    batch_size: i64,
    max_unavailable: i64,
    pause_seconds: f64,
) -> Result<Value, ApiError> {
    let services = Value::Array(
        specs.into_iter()
            .map(|item| {
                json!({
                    "code": item.code,
                    "replicas": item.replicas.max(1),
                })
            })
            .collect(),
    );
    admin.set_bindings_runtime(
        node_id,
        order,
        Some(services),
        reconcile,
        Some(strategy),
        Some(batch_size.max(1)),
        Some(max_unavailable.max(0)),
        Some(pause_seconds.max(0.0)),
    )
}

fn print_desired_services(out: &Value) {
    let desired = out
        .get("desired_services")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();
    let replicas = out
        .get("desired_service_replicas")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let disabled = out
        .get("disabled_services")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();

    crate::console::info(&format!(
        "Desired: {}",
        if desired.is_empty() {
            "-".to_string()
        } else {
            desired.join(", ")
        }
    ));

    if !replicas.is_empty() {
        let mut parts = Vec::new();
        for code in &desired {
            let replicas = replicas
                .get(code)
                .and_then(|v| v.as_i64())
                .unwrap_or(1)
                .max(1);
            parts.push(format!("{code}={replicas}"));
        }
        for (code, value) in &replicas {
            if !desired.iter().any(|v| v == code) {
                parts.push(format!("{}={}", code, value.as_i64().unwrap_or(1).max(1)));
            }
        }
        if !parts.is_empty() {
            crate::console::info(&format!("Replicas: {}", parts.join(", ")));
        }
    }

    crate::console::info(&format!(
        "Disabled: {}",
        if disabled.is_empty() {
            "-".to_string()
        } else {
            disabled.join(", ")
        }
    ));

    if let Some(job_id) = out.get("job_id").and_then(|v| v.as_i64()) {
        crate::console::info(&format!("Job queued: {job_id}"));
    }
}

fn as_array(value: &Value) -> Vec<Map<String, Value>> {
    value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_object().cloned())
        .collect()
}

fn field_text(row: &Map<String, Value>, key: &str) -> String {
    match row.get(key) {
        Some(Value::Null) | None => "-".to_string(),
        Some(Value::String(v)) => {
            if v.trim().is_empty() {
                "-".to_string()
            } else {
                v.to_string()
            }
        }
        Some(v) => v.to_string(),
    }
}

fn client_from_base(base_override: Option<&str>) -> io::Result<ApiClient> {
    let cfg = load_config()?;
    let base = normalize_base_url(base_override.unwrap_or(&cfg.base_url));
    ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn fail_admin(err: ApiError, action: &str) -> io::Result<i32> {
    crate::console::err(&format_admin_error(&err, action));
    Ok(2)
}

fn format_admin_error(err: &ApiError, action: &str) -> String {
    if err.status_code == 401 || err.status_code == 403 {
        "Unauthorized. Admin access is required.".to_string()
    } else {
        format!("Failed to {action}: {}", err.message)
    }
}

fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    } else {
        println!("{v}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_binding_manifest, apply_role_binding_manifest, apply_role_manifest,
        daemonset_matches_node, daemonset_selector, deployment_node_ref, deployment_rollout,
        metadata_project, pod_manifest_to_service_yaml,
    };
    use serde_json::json;

    #[test]
    fn pod_manifest_converts_to_legacy_service_yaml() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: Pod
metadata:
  name: nginx-web
  project: edge-eu
  annotations:
    saharo.io/display-name: Nginx Web Server
spec:
  containers:
    - name: app
      image: nginx:alpine
      ports:
        - "8080:80/tcp"
  restartPolicy: UnlessStopped
  health:
    enabled: true
    checkCommand: "test -f /tmp/ok"
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse pod");
        let map = parsed.as_mapping().expect("pod object");
        let output = pod_manifest_to_service_yaml(map).expect("convert pod");
        let legacy: serde_yaml::Value = serde_yaml::from_str(&output).expect("parse legacy yaml");
        let legacy_map = legacy.as_mapping().expect("legacy object");

        assert_eq!(
            legacy_map
                .get(serde_yaml::Value::String("name".to_string()))
                .and_then(|v| v.as_str()),
            Some("nginx-web")
        );
        assert_eq!(
            legacy_map
                .get(serde_yaml::Value::String("display_name".to_string()))
                .and_then(|v| v.as_str()),
            Some("Nginx Web Server")
        );
        let legacy_metadata = legacy_map
            .get(serde_yaml::Value::String("metadata".to_string()))
            .and_then(|v| v.as_mapping())
            .expect("legacy metadata");
        assert_eq!(
            legacy_metadata
                .get(serde_yaml::Value::String("project".to_string()))
                .and_then(|v| v.as_str()),
            Some("edge-eu")
        );
        let container = legacy_map
            .get(serde_yaml::Value::String("container".to_string()))
            .and_then(|v| v.as_mapping())
            .expect("container");
        assert_eq!(
            container
                .get(serde_yaml::Value::String("image".to_string()))
                .and_then(|v| v.as_str()),
            Some("nginx:alpine")
        );
        assert_eq!(
            container
                .get(serde_yaml::Value::String("restart_policy".to_string()))
                .and_then(|v| v.as_str()),
            Some("unless-stopped")
        );
    }

    #[test]
    fn deployment_node_ref_supports_transitional_paths() {
        let input = r#"
spec:
  podRef: nginx-web
  placement:
    nodeSelector:
      nodeRef: edge-1
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse deployment");
        let spec = parsed
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("spec".to_string())))
            .and_then(|v| v.as_mapping())
            .expect("spec");
        assert_eq!(deployment_node_ref(spec).as_deref(), Some("edge-1"));
    }

    #[test]
    fn deployment_rollout_maps_strategy_names() {
        let input = r#"
spec:
  strategy:
    type: RollingUpdate
    batchSize: 2
    maxUnavailable: 0
    pauseSeconds: 1
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse deployment");
        let spec = parsed
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("spec".to_string())))
            .and_then(|v| v.as_mapping())
            .expect("spec");
        let rollout = deployment_rollout(spec).expect("rollout");
        assert_eq!(rollout.strategy, "rolling");
        assert_eq!(rollout.batch_size, 2);
        assert_eq!(rollout.max_unavailable, 0);
        assert_eq!(rollout.pause_seconds, 1.0);
    }

    #[test]
    fn binding_manifest_validates_in_pinned_mode() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: Binding
metadata:
  name: nginx-web-edge-1
  project: edge-eu
spec:
  targetKind: Deployment
  targetRef: nginx-web
  nodeRef: edge-1
  mode: Pinned
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse binding");
        let map = parsed.as_mapping().expect("binding object");
        let code = apply_binding_manifest(map, true, None, false).expect("validate binding");
        assert_eq!(code, 0);
    }

    #[test]
    fn binding_manifest_rejects_preferred_mode_for_now() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: Binding
metadata:
  name: nginx-web-edge-1
  project: edge-eu
spec:
  targetKind: Deployment
  targetRef: nginx-web
  nodeRef: edge-1
  mode: Preferred
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse binding");
        let map = parsed.as_mapping().expect("binding object");
        let err = apply_binding_manifest(map, true, None, false).expect_err("preferred rejected");
        assert!(
            err.to_string().contains("Only `Pinned` is currently implemented."),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn daemonset_selector_matches_supported_node_fields() {
        let input = r#"
spec:
  placement:
    nodeSelector:
      region: eu
      enabled: true
    denyNodes:
      - edge-2
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse daemonset");
        let spec = parsed
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("spec".to_string())))
            .and_then(|v| v.as_mapping())
            .expect("spec");
        let selector = daemonset_selector(spec).expect("selector");
        let good_node = json!({
            "id": 1,
            "name": "edge-1",
            "public_host": "edge-1.example.com",
            "region_code": "eu",
            "enabled": true,
            "maintenance": false
        });
        let denied_node = json!({
            "id": 2,
            "name": "edge-2",
            "public_host": "edge-2.example.com",
            "region_code": "eu",
            "enabled": true,
            "maintenance": false
        });
        let wrong_region = json!({
            "id": 3,
            "name": "edge-3",
            "public_host": "edge-3.example.com",
            "region_code": "us",
            "enabled": true,
            "maintenance": false
        });

        assert!(daemonset_matches_node(&good_node, &selector));
        assert!(!daemonset_matches_node(&denied_node, &selector));
        assert!(!daemonset_matches_node(&wrong_region, &selector));
    }

    #[test]
    fn pod_manifest_requires_project_metadata() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: Pod
metadata:
  name: nginx-web
spec:
  containers:
    - name: app
      image: nginx:alpine
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse pod");
        let map = parsed.as_mapping().expect("pod object");
        assert_eq!(metadata_project(map), None);
    }

    #[test]
    fn role_manifest_validates_project_scope() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: Role
metadata:
  name: edge-operator
spec:
  rules:
    - effect: allow
      resources: [deployments, pods]
      verbs: [get, list, apply]
      scope:
        type: project
        workspace: prod
        project: edge-eu
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse role");
        let map = parsed.as_mapping().expect("role object");
        let code = apply_role_manifest(input, map, true, None, false).expect("validate role");
        assert_eq!(code, 0);
    }

    #[test]
    fn role_manifest_rejects_missing_workspace_for_project_scope() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: Role
metadata:
  name: edge-operator
spec:
  rules:
    - effect: allow
      resources: [deployments]
      verbs: [apply]
      scope:
        type: project
        project: edge-eu
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse role");
        let map = parsed.as_mapping().expect("role object");
        let err = apply_role_manifest(input, map, true, None, false).expect_err("role validation must fail");
        assert!(err.to_string().contains("scope.workspace"));
    }

    #[test]
    fn role_binding_manifest_validates_user_subject() {
        let input = r#"
apiVersion: saharo.io/v1alpha1
kind: RoleBinding
metadata:
  name: alice-edge-operator
spec:
  subject:
    kind: User
    name: alice
  roleRef:
    name: edge-operator
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(input).expect("parse role binding");
        let map = parsed.as_mapping().expect("role binding object");
        let code = apply_role_binding_manifest(input, map, true, None, false).expect("validate role binding");
        assert_eq!(code, 0);
    }
}
