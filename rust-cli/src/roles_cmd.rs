use std::fs;
use std::io;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use dialoguer::{theme::ColorfulTheme, Input, MultiSelect, Select};
use saharo_sdk::{AdminFacade, ApiClient, ApiError};
use serde_json::{json, Value as JsonValue};
use serde_yaml::{Mapping, Value};

use crate::config::{load_config, normalize_base_url};
use crate::{
    GetRoleArgs, GetRoleBindingArgs, GetRoleBindingsArgs, GetRolesArgs, RoleEffect, RoleInitArgs,
    RoleScopeType,
};

const CANONICAL_ROLE_RESOURCES: &[&str] = &[
    "pods",
    "deployments",
    "daemonsets",
    "bindings",
    "nodes",
    "audit",
    "jobs",
    "users",
    "roles",
    "rolebindings",
    "invites",
    "host",
    "*",
];

const CANONICAL_ROLE_VERBS: &[&str] = &[
    "get",
    "list",
    "watch",
    "create",
    "update",
    "delete",
    "apply",
    "assign",
    "reconcile",
    "*",
];

pub fn init_role_manifest(args: RoleInitArgs) -> io::Result<i32> {
    let resolved = if args.interactive
        || args.name.is_none()
        || args.effect.is_none()
        || args.scope.is_none()
        || args.resources.is_empty()
        || args.verbs.is_empty()
    {
        prompt_role_spec(args)?
    } else {
        resolve_role_spec(args)?
    };

    let yaml = serde_yaml::to_string(&resolved.to_value())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid role manifest: {e}")))?;

    if let Some(path) = resolved.output.as_deref() {
        fs::write(path, &yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to write file: {e}")))?;
        crate::console::ok(&format!("Role manifest written to {path}."));
    } else {
        println!("{yaml}");
    }

    Ok(0)
}

pub fn get_roles(args: GetRolesArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_roles_raw() {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list roles"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    let rows = data.as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        crate::console::info("No roles found.");
        return Ok(0);
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "name", "created_by_user_id", "updated_at"]);
    for role in rows {
        table.add_row(vec![
            value_text(role.get("id")),
            value_text(role.get("name")),
            value_text(role.get("created_by_user_id")),
            value_text(role.get("updated_at")),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_role(args: GetRoleArgs, describe: bool) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let role_id = match resolve_role_id(&admin, args.role_ref.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let data = match admin.get_role_raw(role_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get role"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&data);
    } else {
        let out = json!({
            "id": data.get("id").cloned().unwrap_or(JsonValue::Null),
            "name": data.get("name").cloned().unwrap_or(JsonValue::Null),
            "created_by_user_id": data.get("created_by_user_id").cloned().unwrap_or(JsonValue::Null),
            "updated_at": data.get("updated_at").cloned().unwrap_or(JsonValue::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn get_role_bindings(args: GetRoleBindingsArgs) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let data = match admin.list_role_bindings_raw() {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "list role bindings"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    let rows = data.as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        crate::console::info("No role bindings found.");
        return Ok(0);
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "name", "subject_user_id", "role_name", "updated_at"]);
    for binding in rows {
        table.add_row(vec![
            value_text(binding.get("id")),
            value_text(binding.get("name")),
            value_text(binding.get("subject_user_id")),
            value_text(binding.get("role_name")),
            value_text(binding.get("updated_at")),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_role_binding(args: GetRoleBindingArgs, describe: bool) -> io::Result<i32> {
    let client = client_from_base(args.base_url.as_deref())?;
    let admin = AdminFacade::new(&client);
    let binding_id = match resolve_role_binding_id(&admin, args.role_binding_ref.as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            crate::console::err(&msg);
            return Ok(2);
        }
    };
    let data = match admin.get_role_binding_raw(binding_id) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "get role binding"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&data);
    } else {
        let out = json!({
            "id": data.get("id").cloned().unwrap_or(JsonValue::Null),
            "name": data.get("name").cloned().unwrap_or(JsonValue::Null),
            "subject_user_id": data.get("subject_user_id").cloned().unwrap_or(JsonValue::Null),
            "role_name": data.get("role_name").cloned().unwrap_or(JsonValue::Null),
            "updated_at": data.get("updated_at").cloned().unwrap_or(JsonValue::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

#[derive(Clone)]
struct ResolvedRoleSpec {
    name: String,
    effect: RoleEffect,
    resources: Vec<String>,
    verbs: Vec<String>,
    scope: RoleScopeType,
    workspace: Option<String>,
    project: Option<String>,
    kind: Option<String>,
    object_name: Option<String>,
    output: Option<String>,
}

impl ResolvedRoleSpec {
    fn to_value(&self) -> Value {
        let mut metadata = Mapping::new();
        metadata.insert(vs("name"), vs(&self.name));

        let mut scope = Mapping::new();
        scope.insert(vs("type"), vs(scope_name(self.scope)));
        if let Some(workspace) = self.workspace.as_deref() {
            scope.insert(vs("workspace"), vs(workspace));
        }
        if let Some(project) = self.project.as_deref() {
            scope.insert(vs("project"), vs(project));
        }
        if let Some(kind) = self.kind.as_deref() {
            scope.insert(vs("kind"), vs(kind));
        }
        if let Some(object_name) = self.object_name.as_deref() {
            scope.insert(vs("name"), vs(object_name));
        }

        let mut rule = Mapping::new();
        rule.insert(vs("effect"), vs(effect_name(self.effect)));
        rule.insert(
            vs("resources"),
            Value::Sequence(self.resources.iter().map(|v| vs(v)).collect()),
        );
        rule.insert(
            vs("verbs"),
            Value::Sequence(self.verbs.iter().map(|v| vs(v)).collect()),
        );
        rule.insert(vs("scope"), Value::Mapping(scope));

        let mut spec = Mapping::new();
        spec.insert(vs("rules"), Value::Sequence(vec![Value::Mapping(rule)]));

        let mut root = Mapping::new();
        root.insert(vs("apiVersion"), vs("saharo.io/v1alpha1"));
        root.insert(vs("kind"), vs("Role"));
        root.insert(vs("metadata"), Value::Mapping(metadata));
        root.insert(vs("spec"), Value::Mapping(spec));
        Value::Mapping(root)
    }
}

fn prompt_role_spec(args: RoleInitArgs) -> io::Result<ResolvedRoleSpec> {
    let theme = ColorfulTheme::default();
    let name = if let Some(name) = args.name {
        validate_non_empty("role name", &name)?
    } else {
        Input::<String>::with_theme(&theme)
            .with_prompt("Role name")
            .interact_text()
            .map_err(to_io)?
    };

    let effect = if let Some(effect) = args.effect {
        effect
    } else {
        let items = ["allow", "deny"];
        let idx = Select::with_theme(&theme)
            .with_prompt("Rule effect")
            .items(&items)
            .default(0)
            .interact()
            .map_err(to_io)?;
        [RoleEffect::Allow, RoleEffect::Deny][idx]
    };

    let scope = if let Some(scope) = args.scope {
        scope
    } else {
        let items = ["global", "workspace", "project", "object"];
        let idx = Select::with_theme(&theme)
            .with_prompt("Scope type")
            .items(&items)
            .default(2)
            .interact()
            .map_err(to_io)?;
        [
            RoleScopeType::Global,
            RoleScopeType::Workspace,
            RoleScopeType::Project,
            RoleScopeType::Object,
        ][idx]
    };

    let resources = if args.resources.is_empty() {
        let choices = CANONICAL_ROLE_RESOURCES;
        let selected = MultiSelect::with_theme(&theme)
            .with_prompt("Resources")
            .items(&choices)
            .interact()
            .map_err(to_io)?;
        if selected.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "at least one resource is required"));
        }
        selected.into_iter().map(|idx| choices[idx].to_string()).collect()
    } else {
        split_csv_values(&args.resources)
    };

    let verbs = if args.verbs.is_empty() {
        let choices = CANONICAL_ROLE_VERBS;
        let selected = MultiSelect::with_theme(&theme)
            .with_prompt("Verbs")
            .items(&choices)
            .interact()
            .map_err(to_io)?;
        if selected.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "at least one verb is required"));
        }
        selected.into_iter().map(|idx| choices[idx].to_string()).collect()
    } else {
        split_csv_values(&args.verbs)
    };

    let mut workspace = args.workspace;
    let mut project = args.project;
    let mut kind = args.kind;
    let mut object_name = args.object_name;

    if matches!(scope, RoleScopeType::Workspace | RoleScopeType::Project | RoleScopeType::Object)
        && workspace.as_deref().unwrap_or("").trim().is_empty()
    {
        workspace = Some(
            Input::<String>::with_theme(&theme)
                .with_prompt("Workspace")
                .interact_text()
                .map_err(to_io)?,
        );
    }
    if matches!(scope, RoleScopeType::Project | RoleScopeType::Object)
        && project.as_deref().unwrap_or("").trim().is_empty()
    {
        project = Some(
            Input::<String>::with_theme(&theme)
                .with_prompt("Project")
                .interact_text()
                .map_err(to_io)?,
        );
    }
    if matches!(scope, RoleScopeType::Object) && kind.as_deref().unwrap_or("").trim().is_empty() {
        kind = Some(
            Input::<String>::with_theme(&theme)
                .with_prompt("Object kind")
                .interact_text()
                .map_err(to_io)?,
        );
    }
    if matches!(scope, RoleScopeType::Object)
        && object_name.as_deref().unwrap_or("").trim().is_empty()
    {
        object_name = Some(
            Input::<String>::with_theme(&theme)
                .with_prompt("Object name")
                .interact_text()
                .map_err(to_io)?,
        );
    }

    resolve_role_spec(RoleInitArgs {
        name: Some(name),
        interactive: args.interactive,
        effect: Some(effect),
        resources,
        verbs,
        scope: Some(scope),
        workspace,
        project,
        kind,
        object_name,
        output: args.output,
    })
}

fn resolve_role_spec(args: RoleInitArgs) -> io::Result<ResolvedRoleSpec> {
    let name = validate_non_empty("role name", args.name.as_deref().unwrap_or(""))?;
    let effect = args.effect.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--effect is required"))?;
    let scope = args.scope.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--scope is required"))?;
    let resources = split_csv_values(&args.resources);
    if resources.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "at least one --resource is required"));
    }
    let invalid_resources = resources
        .iter()
        .map(|item| item.to_lowercase())
        .filter(|item| !CANONICAL_ROLE_RESOURCES.contains(&item.as_str()))
        .collect::<Vec<_>>();
    if !invalid_resources.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported resources: {}", invalid_resources.join(", ")),
        ));
    }
    let verbs = split_csv_values(&args.verbs);
    if verbs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "at least one --verb is required"));
    }
    let invalid_verbs = verbs
        .iter()
        .map(|item| item.to_lowercase())
        .filter(|item| !CANONICAL_ROLE_VERBS.contains(&item.as_str()))
        .collect::<Vec<_>>();
    if !invalid_verbs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported verbs: {}", invalid_verbs.join(", ")),
        ));
    }

    let workspace = normalize_optional(args.workspace);
    let project = normalize_optional(args.project);
    let kind = normalize_optional(args.kind);
    let object_name = normalize_optional(args.object_name);

    match scope {
        RoleScopeType::Global => {}
        RoleScopeType::Workspace => {
            require_field("workspace", workspace.as_deref())?;
        }
        RoleScopeType::Project => {
            require_field("workspace", workspace.as_deref())?;
            require_field("project", project.as_deref())?;
        }
        RoleScopeType::Object => {
            require_field("workspace", workspace.as_deref())?;
            require_field("project", project.as_deref())?;
            require_field("kind", kind.as_deref())?;
            require_field("object-name", object_name.as_deref())?;
        }
    }

    Ok(ResolvedRoleSpec {
        name,
        effect,
        resources,
        verbs,
        scope,
        workspace,
        project,
        kind,
        object_name,
        output: normalize_optional(args.output),
    })
}

fn split_csv_values(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in values {
        for part in raw.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !out.iter().any(|v| v == trimmed) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

fn validate_non_empty(field: &str, value: &str) -> io::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} is required"),
        ))
    } else {
        Ok(trimmed.to_string())
    }
}

fn require_field(field: &str, value: Option<&str>) -> io::Result<()> {
    if value.map(|v| !v.trim().is_empty()).unwrap_or(false) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--{field} is required for this scope"),
        ))
    }
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn effect_name(effect: RoleEffect) -> &'static str {
    match effect {
        RoleEffect::Allow => "allow",
        RoleEffect::Deny => "deny",
    }
}

fn scope_name(scope: RoleScopeType) -> &'static str {
    match scope {
        RoleScopeType::Global => "global",
        RoleScopeType::Workspace => "workspace",
        RoleScopeType::Project => "project",
        RoleScopeType::Object => "object",
    }
}

fn vs(value: &str) -> Value {
    Value::String(value.to_string())
}

fn to_io(err: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn client_from_base(base_url: Option<&str>) -> io::Result<ApiClient> {
    let cfg = load_config()?;
    let base = normalize_base_url(base_url.unwrap_or(&cfg.base_url));
    ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn resolve_role_id(admin: &AdminFacade<'_>, role_ref: Option<&str>) -> Result<i64, String> {
    let role_ref = match role_ref {
        Some(v) if !v.trim().is_empty() => v.trim(),
        _ => return Err("Role id or name is required.".to_string()),
    };
    admin.resolve_role_id(role_ref)
}

fn resolve_role_binding_id(
    admin: &AdminFacade<'_>,
    role_binding_ref: Option<&str>,
) -> Result<i64, String> {
    let role_binding_ref = match role_binding_ref {
        Some(v) if !v.trim().is_empty() => v.trim(),
        _ => return Err("Role binding id or name is required.".to_string()),
    };
    if role_binding_ref.chars().all(|c| c.is_ascii_digit()) {
        return role_binding_ref
            .parse::<i64>()
            .map_err(|_| "Invalid role binding id.".to_string());
    }
    let raw = admin
        .get_role_binding_by_name_raw(role_binding_ref)
        .map_err(|e| e.message)?;
    raw.get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "Invalid role binding id in response.".to_string())
}

fn print_json(value: &JsonValue) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string()));
}

fn value_text(value: Option<&JsonValue>) -> String {
    match value {
        Some(JsonValue::Null) | None => String::new(),
        Some(JsonValue::String(v)) => v.clone(),
        Some(JsonValue::Bool(v)) => v.to_string(),
        Some(JsonValue::Number(v)) => v.to_string(),
        Some(other) => other.to_string(),
    }
}

fn fail_admin(err: ApiError, action: &str) -> io::Result<i32> {
    crate::console::err(&format!("{action} failed: {}", err.message));
    Ok(match err.status_code {
        400..=499 => 2,
        _ => 1,
    })
}
