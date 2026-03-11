use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod auth;
mod config;
mod console;
mod health;
mod host_join;
mod invites_cmd;
mod k8s_cmd;
mod portal_cmd;
mod pretty_kv;
mod principal_cmd;
mod registry;
mod roles_cmd;
mod services_cmd;
mod settings;
mod updates_cmd;
mod vpn_config;

#[derive(Parser, Debug)]
#[command(
    name = "saharoctl",
    bin_name = "saharoctl",
    about = "saharo control plane CLI",
    version,
    styles = cli_styles()
)]
struct Cli {
    /// Verbose logs.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn cli_styles() -> Styles {
    Styles::styled()
        .header(
            AnsiColor::BrightBlue
                .on_default()
                .effects(Effects::BOLD | Effects::UNDERLINE),
        )
        .usage(AnsiColor::BrightBlue.on_default().effects(Effects::BOLD))
        .literal(AnsiColor::BrightCyan.on_default().effects(Effects::BOLD))
        .placeholder(AnsiColor::BrightYellow.on_default())
        .error(AnsiColor::BrightRed.on_default().effects(Effects::BOLD))
        .valid(AnsiColor::BrightGreen.on_default().effects(Effects::BOLD))
        .invalid(AnsiColor::BrightYellow.on_default().effects(Effects::BOLD))
        .context(AnsiColor::BrightBlack.on_default())
        .context_value(AnsiColor::BrightMagenta.on_default())
}

#[derive(Subcommand, Debug)]
enum Commands {
    Settings(SettingsArgs),
    Auth(AuthArgs),
    Config(ConfigArgs),
    Health(HealthArgsCommand),
    Whoami(WhoamiArgs),
    Get(GetArgs),
    Describe(DescribeArgs),
    Delete(DeleteArgs),
    Logs(KubeLogsArgs),
    Join(JoinArgs),
    Apply(ApplyArgs),
    Assign(AssignArgs),
    Unassign(UnassignArgs),
    Init(InitArgs),
    Users(UsersArgs),
    Invites(InvitesArgs),
    Reconcile(ReconcileArgs),
    Update(UpdateArgs),
    Portal(PortalArgs),
}

#[derive(Args, Debug)]
struct SettingsArgs {
    #[command(subcommand)]
    command: SettingsCommand,
}

#[derive(Subcommand, Debug)]
enum SettingsCommand {
    Init(SettingsInitArgs),
    Show,
    Get(KeyArg),
    Set(SettingsSetArgs),
}

#[derive(Args, Debug)]
struct SettingsInitArgs {
    #[arg(long)]
    force: bool,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Args, Debug)]
struct SettingsSetArgs {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    license_api_url: Option<String>,
}

#[derive(Args, Debug)]
struct KeyArg {
    key: String,
}

#[derive(Args, Debug)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Subcommand, Debug)]
enum AuthCommand {
    Login(AuthLoginArgs),
    LoginApiKey(AuthLoginApiKeyArgs),
    Register(AuthRegisterArgs),
    Logout(AuthLogoutArgs),
    #[command(hide = true)]
    Activate,
    Status(AuthStatusArgs),
    #[command(hide = true)]
    Whoami(WhoamiArgs),
}

#[derive(Args, Debug, Clone)]
struct WhoamiArgs {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    verbose: bool,
}

#[derive(Args, Debug, Clone)]
struct AuthLoginArgs {
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct AuthLoginApiKeyArgs {
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct AuthRegisterArgs {
    invite_token: String,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "device")]
    device_label: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct AuthLogoutArgs {
    #[arg(long = "docker", default_value_t = true, action = clap::ArgAction::Set)]
    docker: bool,
    #[arg(long = "no-docker", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_docker: bool,
}

#[derive(Args, Debug, Clone)]
struct AuthStatusArgs {
    #[arg(long)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Get(ConfigGetArgs),
}

#[derive(Args, Debug, Clone)]
struct ConfigGetArgs {
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    protocol: Option<String>,
    #[arg(long)]
    route: Option<String>,
    #[arg(long)]
    device: Option<String>,
    #[arg(long)]
    out: Option<String>,
    #[arg(long)]
    conf: bool,
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct HealthArgsCommand {
    #[arg(long = "json")]
    json_output: bool,
    #[arg(long)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct GetArgs {
    #[command(subcommand)]
    resource: GetResource,
}

#[derive(Subcommand, Debug)]
enum GetResource {
    Nodes(GetNodesArgs),
    Node(GetNodeArgs),
    Jobs(GetJobsArgs),
    Job(GetJobArgs),
    Pods(GetPodsArgs),
    Pod(GetPodArgs),
    Deployments(GetDeploymentsArgs),
    Deployment(GetDeploymentArgs),
    DeploymentRevisions(GetDeploymentRevisionsArgs),
    Bindings(GetBindingsArgs),
    Binding(GetBindingArgs),
    Users(GetUsersArgs),
    User(GetUserArgs),
    Grants(GetGrantsArgs),
    Grant(GetGrantArgs),
    Invites(GetInvitesArgs),
    Invite(GetInviteArgs),
    Roles(GetRolesArgs),
    Role(GetRoleArgs),
    RoleBindings(GetRoleBindingsArgs),
    RoleBinding(GetRoleBindingArgs),
    Releases(GetReleasesArgs),
    Release(GetReleaseArgs),
}

#[derive(Args, Debug, Clone)]
struct GetNodesArgs {
    #[arg(long)]
    q: Option<String>,
    #[arg(long, default_value_t = 1)]
    page: i64,
    #[arg(long = "page-size", default_value_t = 50)]
    page_size: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetNodeArgs {
    node_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetJobsArgs {
    #[arg(long)]
    status: Option<String>,
    #[arg(long = "node")]
    node: Option<String>,
    #[arg(long = "agent-id")]
    agent_id: Option<i64>,
    #[arg(long, default_value_t = 1)]
    page: i64,
    #[arg(long = "page-size", default_value_t = 50)]
    page_size: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetJobArgs {
    job_id: Option<i64>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetPodsArgs {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetPodArgs {
    pod_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetDeploymentsArgs {
    #[arg(long = "enabled-only", default_value_t = false)]
    enabled_only: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetDeploymentArgs {
    deployment_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetDeploymentRevisionsArgs {
    deployment_ref: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetBindingsArgs {
    #[arg(long = "kind")]
    binding_kind: Option<String>,
    #[arg(long = "node")]
    node: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetBindingArgs {
    binding_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetUsersArgs {
    #[arg(long)]
    q: Option<String>,
    #[arg(long, default_value_t = 1)]
    page: i64,
    #[arg(long = "page-size", default_value_t = 50)]
    page_size: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetUserArgs {
    user_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetGrantsArgs {
    #[arg(long = "user")]
    user_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetGrantArgs {
    grant_id: Option<i64>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetInvitesArgs {
    #[arg(long, default_value_t = 1)]
    page: i64,
    #[arg(long = "page-size", default_value_t = 50)]
    page_size: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetInviteArgs {
    invite_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct UsersArgs {
    #[command(subcommand)]
    command: UsersCommand,
}

#[derive(Subcommand, Debug)]
enum UsersCommand {
    Get(GetUsersArgs),
    Describe(GetUserArgs),
    SetRole(SetUserRoleArgs),
}

#[derive(Args, Debug, Clone)]
struct SetUserRoleArgs {
    user_ref: String,
    role: String,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct InvitesArgs {
    #[command(subcommand)]
    command: InvitesCommand,
}

#[derive(Subcommand, Debug)]
enum InvitesCommand {
    Get(GetInvitesArgs),
    Describe(GetInviteArgs),
    CreateUser(CreateUserInviteArgs),
}

#[derive(Args, Debug, Clone)]
struct CreateUserInviteArgs {
    #[arg(long = "duration-days")]
    duration_days: Option<i64>,
    #[arg(long, default_value_t = false)]
    perpetual: bool,
    #[arg(long)]
    note: Option<String>,
    #[arg(long = "max-uses", default_value_t = 1)]
    max_uses: i64,
    #[arg(long = "expires-in-days", default_value_t = 30)]
    expires_in_days: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct InitArgs {
    #[command(subcommand)]
    resource: InitResource,
}

#[derive(Subcommand, Debug)]
enum InitResource {
    Role(RoleInitArgs),
}

#[derive(Args, Debug, Clone)]
struct RoleInitArgs {
    name: Option<String>,
    #[arg(long, default_value_t = false)]
    interactive: bool,
    #[arg(long)]
    effect: Option<RoleEffect>,
    #[arg(long = "resource")]
    resources: Vec<String>,
    #[arg(long = "verb")]
    verbs: Vec<String>,
    #[arg(long)]
    scope: Option<RoleScopeType>,
    #[arg(long)]
    workspace: Option<String>,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long = "object-name")]
    object_name: Option<String>,
    #[arg(long)]
    output: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct GetRolesArgs {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetRoleArgs {
    role_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetRoleBindingsArgs {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetRoleBindingArgs {
    role_binding_ref: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum RoleEffect {
    Allow,
    Deny,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum RoleScopeType {
    Global,
    Workspace,
    Project,
    Object,
}

#[derive(Args, Debug, Clone)]
struct GetReleasesArgs {
    #[arg(long, default_value = "stable")]
    channel: String,
    #[arg(long, default_value_t = 50)]
    limit: i64,
    #[arg(long = "license-api-url")]
    license_api_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct GetReleaseArgs {
    version: Option<String>,
    #[arg(long, default_value = "stable")]
    channel: String,
    #[arg(long, default_value_t = 100)]
    limit: i64,
    #[arg(long = "license-api-url")]
    license_api_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct DescribeArgs {
    #[command(subcommand)]
    resource: DescribeResource,
}

#[derive(Subcommand, Debug)]
enum DescribeResource {
    Node(GetNodeArgs),
    Job(GetJobArgs),
    Pod(GetPodArgs),
    Deployment(GetDeploymentArgs),
    Binding(GetBindingArgs),
    BindingDrift(GetBindingDriftArgs),
    User(GetUserArgs),
    Grant(GetGrantArgs),
    Invite(GetInviteArgs),
    Role(GetRoleArgs),
    RoleBinding(GetRoleBindingArgs),
    Release(GetReleaseArgs),
}

#[derive(Args, Debug, Clone)]
struct GetBindingDriftArgs {
    #[arg(long = "node")]
    node: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct DeleteArgs {
    #[command(subcommand)]
    resource: DeleteResource,
}

#[derive(Subcommand, Debug)]
enum DeleteResource {
    Node(DeleteNodeArgs),
    Grant(DeleteGrantArgs),
    Jobs(DeleteJobsArgs),
    Host(DeleteHostArgs),
}

#[derive(Args, Debug, Clone)]
struct DeleteNodeArgs {
    node_ref: Option<String>,
    #[arg(long = "force", default_value_t = true, action = clap::ArgAction::Set)]
    force: bool,
    #[arg(long = "no-force", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_force: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct UnassignDeploymentArgs {
    #[arg(long = "node")]
    node: Option<String>,
    #[arg(long = "deployment")]
    deployments: Vec<String>,
    #[arg(long, default_value_t = false)]
    all: bool,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    reconcile: bool,
    #[arg(long = "no-reconcile", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_reconcile: bool,
    #[arg(long, default_value = "safe")]
    strategy: String,
    #[arg(long = "batch-size", default_value_t = 1)]
    batch_size: i64,
    #[arg(long = "max-unavailable", default_value_t = 1)]
    max_unavailable: i64,
    #[arg(long = "pause-seconds", default_value_t = 0.0)]
    pause_seconds: f64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct DeleteGrantArgs {
    grant_id: Option<i64>,
    #[arg(long, short = 'f', default_value_t = false)]
    force: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct DeleteJobsArgs {
    #[arg(long = "older-than-days")]
    older_than_days: Option<i64>,
    #[arg(long)]
    status: Option<String>,
    #[arg(long = "node-id")]
    node_id: Option<i64>,
    #[arg(long = "agent-id")]
    agent_id: Option<i64>,
    #[arg(long = "dry-run", default_value_t = false)]
    dry_run: bool,
    #[arg(long, default_value_t = false)]
    yes: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct DeleteHostArgs {
    #[arg(long = "license-id")]
    license_id: Option<String>,
    #[arg(long = "lic-url")]
    lic_url: Option<String>,
    #[arg(long, default_value_t = false)]
    force: bool,
}

#[derive(Args, Debug)]
struct KubeLogsArgs {
    #[command(subcommand)]
    resource: LogsResource,
}

#[derive(Subcommand, Debug)]
enum LogsResource {
    Node(NodeLogsArgs),
    Api(ApiLogsArgs),
    Runtime(RuntimeLogsArgs),
}

#[derive(Args, Debug, Clone)]
struct NodeLogsArgs {
    node_ref: Option<String>,
    #[arg(long, default_value_t = 50)]
    lines: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct ApiLogsArgs {
    #[arg(long, default_value_t = false)]
    follow: bool,
    #[arg(long, default_value_t = 200)]
    lines: i64,
}

#[derive(Args, Debug, Clone)]
struct RuntimeLogsArgs {
    node_ref: Option<String>,
    #[arg(long, default_value_t = false)]
    follow: bool,
    #[arg(long, default_value_t = 200)]
    lines: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct JoinArgs {
    #[command(subcommand)]
    resource: JoinResource,
}

#[derive(Subcommand, Debug)]
enum JoinResource {
    Node(JoinNodeArgs),
    Host(JoinHostArgs),
}

#[derive(Args, Debug, Clone)]
struct JoinNodeArgs {
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    note: Option<String>,
    #[arg(long = "ssh")]
    ssh_target: Option<String>,
    #[arg(long = "ssh-user", default_value = "root")]
    ssh_user: String,
    #[arg(long = "port", default_value_t = 22)]
    ssh_port: i64,
    #[arg(long = "key")]
    ssh_key: Option<String>,
    #[arg(long = "password", default_value_t = false)]
    ssh_password_prompt: bool,
    #[arg(long = "sudo", default_value_t = false)]
    sudo: bool,
    #[arg(long = "sudo-password", default_value_t = false)]
    sudo_password_prompt: bool,
    #[arg(long = "local", default_value_t = false)]
    local: bool,
    #[arg(long = "local-path")]
    local_path: Option<String>,
    #[arg(long = "provision-mode", default_value = "auto")]
    provision_mode: String,
    #[arg(long = "api-url")]
    api_url: Option<String>,
    #[arg(long = "dry-run", default_value_t = false)]
    dry_run: bool,
    #[arg(long = "wait", default_value_t = true, action = clap::ArgAction::Set)]
    wait: bool,
    #[arg(long = "no-wait", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_wait: bool,
    #[arg(long = "wait-timeout", default_value_t = 300)]
    wait_timeout: i64,
    #[arg(long = "wait-interval", default_value_t = 5)]
    wait_interval: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct JoinHostArgs {
    #[arg(long)]
    api_url: Option<String>,
    #[arg(long)]
    host_name: Option<String>,
    #[arg(long)]
    x_root_secret: Option<String>,
    #[arg(long)]
    db_password: Option<String>,
    #[arg(long)]
    admin_username: Option<String>,
    #[arg(long)]
    admin_password: Option<String>,
    #[arg(long, default_value = "root")]
    admin_api_key_name: String,
    #[arg(long)]
    telegram_bot_token: Option<String>,
    #[arg(long, default_value = "/opt/saharo")]
    install_dir: String,
    #[arg(long, default_value = "registry.saharoktyan.ru")]
    registry: String,
    #[arg(long)]
    version: Option<String>,
    #[arg(long, default_value = "https://downloads.saharoktyan.ru")]
    lic_url: String,
    #[arg(long, default_value = "1.0.0")]
    tag: String,
    #[arg(long, default_value_t = false)]
    wipe_data: bool,
    #[arg(long, default_value_t = false)]
    confirm_wipe: bool,
    #[arg(long, default_value_t = false)]
    skip_https: bool,
    #[arg(long)]
    https_domain: Option<String>,
    #[arg(long)]
    https_email: Option<String>,
    #[arg(long = "https-http01", default_value_t = true, action = clap::ArgAction::Set)]
    https_http01: bool,
    #[arg(long = "no-https-http01", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_https_http01: bool,
    #[arg(long)]
    vpn_cidr: Option<String>,
    #[arg(long, default_value_t = false)]
    print_versions: bool,
    #[arg(long)]
    enterprise: Option<bool>,
    #[arg(long, default_value_t = false)]
    yes: bool,
    #[arg(long, default_value_t = false)]
    no_docker_install: bool,
    #[arg(long, default_value_t = false)]
    force: bool,
    #[arg(long, default_value_t = false)]
    rotate_jwt_secret: bool,
    #[arg(long)]
    ssh_host: Option<String>,
    #[arg(long = "ssh-user", default_value = "root")]
    ssh_user: String,
    #[arg(long, default_value_t = 22)]
    ssh_port: i64,
    #[arg(long)]
    ssh_key: Option<String>,
    #[arg(long)]
    ssh_password: Option<String>,
    #[arg(long = "ssh-sudo", default_value_t = true, action = clap::ArgAction::Set)]
    ssh_sudo: bool,
    #[arg(long = "no-ssh-sudo", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_ssh_sudo: bool,
    #[arg(long, default_value_t = false)]
    no_pull: bool,
    #[arg(long, default_value_t = 60)]
    health_timeout: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "non-interactive", default_value_t = false)]
    non_interactive: bool,
}

#[derive(Args, Debug)]
struct ApplyArgs {
    #[arg(short = 'f', long = "file")]
    file: String,
    #[arg(long = "dry-run", default_value_t = false)]
    dry_run: bool,
    #[arg(long = "validate-only", default_value_t = false)]
    validate_only: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct AssignArgs {
    #[command(subcommand)]
    resource: AssignResource,
}

#[derive(Subcommand, Debug)]
enum AssignResource {
    Deployment(AssignDeploymentArgs),
}

#[derive(Args, Debug)]
struct UnassignArgs {
    #[command(subcommand)]
    resource: UnassignResource,
}

#[derive(Subcommand, Debug)]
enum UnassignResource {
    Deployment(UnassignDeploymentArgs),
}

#[derive(Args, Debug, Clone)]
struct AssignDeploymentArgs {
    #[arg(long = "node")]
    node: Option<String>,
    #[arg(long = "deployment")]
    deployments: Vec<String>,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    reconcile: bool,
    #[arg(long = "no-reconcile", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_reconcile: bool,
    #[arg(long, default_value = "safe")]
    strategy: String,
    #[arg(long = "batch-size", default_value_t = 1)]
    batch_size: i64,
    #[arg(long = "max-unavailable", default_value_t = 1)]
    max_unavailable: i64,
    #[arg(long = "pause-seconds", default_value_t = 0.0)]
    pause_seconds: f64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}


#[derive(Args, Debug)]
struct ReconcileArgs {
    #[command(subcommand)]
    resource: ReconcileResource,
}

#[derive(Subcommand, Debug)]
enum ReconcileResource {
    Bindings(ReconcileBindingsArgs),
}

#[derive(Args, Debug, Clone)]
struct ReconcileBindingsArgs {
    #[arg(long = "node")]
    node: Option<String>,
    #[arg(long, default_value = "safe")]
    strategy: String,
    #[arg(long = "batch-size", default_value_t = 1)]
    batch_size: i64,
    #[arg(long = "max-unavailable", default_value_t = 1)]
    max_unavailable: i64,
    #[arg(long = "pause-seconds", default_value_t = 0.0)]
    pause_seconds: f64,
    #[arg(long = "dry-run", default_value_t = false)]
    dry_run: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct UpdateArgs {
    #[command(subcommand)]
    target: UpdateTarget,
}

#[derive(Subcommand, Debug)]
enum UpdateTarget {
    Cli(UpdateCliArgs),
    Host(UpdateHostArgs),
    Nodes(UpdateNodesArgs),
}

#[derive(Args, Debug, Clone)]
struct UpdateCliArgs {
    #[arg(long)]
    current: Option<String>,
    #[arg(long)]
    platform: Option<String>,
    #[arg(long = "check-only", default_value_t = false)]
    check_only: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct UpdateHostArgs {
    #[arg(long = "pull-only", default_value_t = false)]
    pull_only: bool,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug, Clone)]
struct UpdateNodesArgs {
    #[arg(long = "node")]
    nodes: Vec<String>,
    #[arg(long = "all", default_value_t = false)]
    all: bool,
    #[arg(long)]
    version: Option<String>,
    #[arg(long = "refresh", default_value_t = true, action = clap::ArgAction::Set)]
    refresh: bool,
    #[arg(long = "no-refresh", default_value_t = false, action = clap::ArgAction::SetTrue)]
    no_refresh: bool,
    #[arg(long = "wait", default_value_t = false)]
    wait: bool,
    #[arg(long = "wait-timeout", default_value_t = 900)]
    wait_timeout: i64,
    #[arg(long = "wait-interval", default_value_t = 5)]
    wait_interval: i64,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long = "json")]
    json_out: bool,
}

#[derive(Args, Debug)]
struct PortalArgs {
    #[command(subcommand)]
    command: PortalCommand,
}

#[derive(Subcommand, Debug)]
enum PortalCommand {
    Auth(PortalAuthArgs),
    Profile(PortalProfileArgs),
    Telemetry(PortalTelemetryArgs),
    Logout(PortalLogoutArgs),
}

#[derive(Args, Debug, Clone)]
struct PortalAuthArgs {
    #[arg(long = "lic-url")]
    lic_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct PortalProfileArgs {
    #[arg(long = "lic-url")]
    lic_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct PortalTelemetryArgs {
    #[arg(long)]
    enable: bool,
    #[arg(long)]
    disable: bool,
    #[arg(long = "lic-url")]
    lic_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct PortalLogoutArgs {
    #[arg(long = "lic-url")]
    lic_url: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let _ = cli.verbose;

    match cli.command {
        None => {
            let mut cmd = Cli::command();
            cmd.print_help().expect("failed to print help");
            println!();
        }
        Some(Commands::Settings(args)) => exit(settings::handle_settings(args.command)),
        Some(Commands::Auth(args)) => exit(auth::handle_auth(args.command)),
        Some(Commands::Config(args)) => exit(vpn_config::handle_config(args.command)),
        Some(Commands::Health(args)) => exit(health::handle_health(args)),
        Some(Commands::Whoami(args)) => exit(auth::whoami(args)),
        Some(Commands::Get(args)) => exit(k8s_cmd::handle_get(args)),
        Some(Commands::Describe(args)) => exit(k8s_cmd::handle_describe(args)),
        Some(Commands::Delete(args)) => exit(k8s_cmd::handle_delete(args)),
        Some(Commands::Logs(args)) => exit(k8s_cmd::handle_logs(args)),
        Some(Commands::Join(args)) => match args.resource {
            JoinResource::Node(a) => exit(k8s_cmd::handle_join(a)),
            JoinResource::Host(a) => exit(host_join::handle_join_host(a)),
        },
        Some(Commands::Apply(args)) => exit(services_cmd::apply_manifest_file(args)),
        Some(Commands::Init(args)) => match args.resource {
            InitResource::Role(a) => exit(roles_cmd::init_role_manifest(a)),
        },
        Some(Commands::Assign(args)) => match args.resource {
            AssignResource::Deployment(a) => exit(services_cmd::assign_deployments(a)),
        },
        Some(Commands::Unassign(args)) => match args.resource {
            UnassignResource::Deployment(a) => exit(services_cmd::unassign_deployments(a)),
        },
        Some(Commands::Users(args)) => match args.command {
            UsersCommand::Get(a) => exit(principal_cmd::get_users(a)),
            UsersCommand::Describe(a) => exit(principal_cmd::get_user(a, true)),
            UsersCommand::SetRole(a) => exit(principal_cmd::set_user_role(a)),
        },
        Some(Commands::Invites(args)) => match args.command {
            InvitesCommand::Get(a) => exit(invites_cmd::get_invites(a)),
            InvitesCommand::Describe(a) => exit(invites_cmd::get_invite(a, true)),
            InvitesCommand::CreateUser(a) => exit(invites_cmd::create_user_invite(a)),
        },
        Some(Commands::Reconcile(args)) => match args.resource {
            ReconcileResource::Bindings(a) => exit(services_cmd::reconcile_bindings(a)),
        },
        Some(Commands::Update(args)) => match args.target {
            UpdateTarget::Cli(a) => exit(updates_cmd::update_cli(a)),
            UpdateTarget::Host(a) => exit(updates_cmd::update_host(a)),
            UpdateTarget::Nodes(a) => exit(updates_cmd::update_nodes(a)),
        },
        Some(Commands::Portal(args)) => exit(portal_cmd::handle_portal(args.command)),
    }
}

fn exit(result: std::io::Result<i32>) {
    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            console::err(&err.to_string());
            std::process::exit(1);
        }
    }
}
