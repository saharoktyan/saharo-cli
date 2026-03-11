pub mod access_facade;
pub mod admin_facade;
pub mod admin_ops;
pub mod api;
pub mod auth_facade;
pub mod awg;
pub mod awg_keys;
pub mod health_facade;
pub mod models;
pub mod vpn_config_facade;

pub use access_facade::{
    build_credentials_ensure_request, resolve_access_target_from_me, AccessFacade,
};
pub use admin_facade::AdminFacade;
pub use admin_ops::{
    build_join_request, execute_join, format_admin_error, format_join_error, parse_job_details,
    parse_jobs_list, parse_node_details, parse_nodes_list, resolve_job_node_id_text,
    resolve_node_id, wait_job, JoinExecutionOptions, JoinExecutionResult, WaitJobResult,
};
pub use api::{cli_protocol, cli_version, ApiClient, ApiError};
pub use auth_facade::{parse_whoami_info, AuthFacade};
pub use awg::{build_awg_conf, build_awg_uri};
pub use awg_keys::{awg_key_dir, load_or_create_awg_keypair, AwgKeypair};
pub use health_facade::{evaluate_cli_compatibility, parse_version_info, HealthFacade};
pub use models::{
    CliCompatibility, CredentialsEnsureInput, CredentialsEnsureRequest, JobDetails, JobSummary,
    JoinNodeRequest, JoinRequestInput, NodeDetails, NodeSummary, VersionInfo, WhoamiAccessEntry,
    WhoamiInfo,
};
pub use vpn_config_facade::{
    awg_output_path, VpnConfigError, VpnConfigFacade, VpnConfigRequest, VpnConfigResult,
};
