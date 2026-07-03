//! Authentication and authorization module for Vultrino RBAC
//!
//! Provides role-based access control for API keys:
//! - Create API keys for different apps/programs
//! - Assign specific permissions (read, write, update, delete, execute)
//! - Scope access to specific credentials or patterns
//! - Optional key expiration

mod approval_tokens;
mod manager;
mod middleware;
mod tokens;
mod types;

pub use approval_tokens::{
    ApprovalToken, ApprovalTokenInvalid, ApprovalTokenMetadata, NewApprovalToken,
    APPROVAL_TOKEN_PREFIX,
};
pub use manager::{AuthManager, AuthManagerError};
pub use middleware::{authenticate, extract_api_key, validate_request, AuthError, AuthResult};
pub use tokens::{
    validate_agent_label, NewUseToken, UseToken, UseTokenInvalid, UseTokenMetadata,
    USE_TOKEN_PREFIX,
};
pub use types::{
    admin_role, executor_role, read_only_role, ApiKey, ApiKeyMetadata, Permission, Role,
    BUILTIN_ROLES, ROLE_ADMIN, ROLE_EXECUTOR, ROLE_READ_ONLY,
};
