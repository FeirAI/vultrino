//! Credential resolution from aliases and patterns

use super::UrlMatcher;
use crate::storage::StorageBackend;
use crate::{Credential, VultrinoError};
use std::sync::Arc;

/// Resolves credential references to actual credentials
pub struct CredentialResolver {
    /// Storage backend for retrieving credentials
    storage: Arc<dyn StorageBackend>,
    /// URL pattern matcher for auto-detection
    url_matcher: UrlMatcher,
}

impl CredentialResolver {
    /// Create a new resolver
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            storage,
            url_matcher: UrlMatcher::new(),
        }
    }

    /// Create a resolver with a URL matcher
    pub fn with_url_matcher(storage: Arc<dyn StorageBackend>, url_matcher: UrlMatcher) -> Self {
        Self {
            storage,
            url_matcher,
        }
    }

    /// Resolve a credential by alias or ID
    pub async fn resolve(&self, alias_or_id: &str) -> Result<Credential, VultrinoError> {
        // Try by alias first
        if let Some(cred) = self.storage.get_by_alias(alias_or_id).await? {
            return Ok(cred);
        }

        // Try by ID
        if let Some(cred) = self.storage.get(alias_or_id).await? {
            return Ok(cred);
        }

        Err(VultrinoError::CredentialNotFound(alias_or_id.to_string()))
    }

    /// Resolve a credential for a URL (auto-detect by pattern)
    pub async fn resolve_for_url(&self, url: &str) -> Result<Option<Credential>, VultrinoError> {
        if let Some(alias) = self.url_matcher.match_url(url) {
            let cred = self.resolve(alias).await?;
            return Ok(Some(cred));
        }
        Ok(None)
    }

    /// Add a URL pattern for auto-detection
    pub fn add_url_pattern(&mut self, pattern: &str, credential_alias: &str) -> Result<(), String> {
        self.url_matcher.add_pattern(pattern, credential_alias)
    }

    /// Get a reference to the URL matcher
    pub fn url_matcher(&self) -> &UrlMatcher {
        &self.url_matcher
    }

    /// Get a mutable reference to the URL matcher
    pub fn url_matcher_mut(&mut self) -> &mut UrlMatcher {
        &mut self.url_matcher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{ApiKey, Role};
    use crate::Secret;
    use crate::{CredentialData, CredentialMetadata};
    use async_trait::async_trait;
    use parking_lot::RwLock;
    use std::collections::HashMap;

    /// Mock storage for testing
    struct MockStorage {
        credentials: RwLock<HashMap<String, Credential>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                credentials: RwLock::new(HashMap::new()),
            }
        }

        fn add(&self, cred: Credential) {
            let mut creds = self.credentials.write();
            creds.insert(cred.id.clone(), cred);
        }
    }

    #[async_trait]
    impl StorageBackend for MockStorage {
        async fn store(&self, credential: &Credential) -> Result<(), crate::storage::StorageError> {
            let mut creds = self.credentials.write();
            creds.insert(credential.id.clone(), credential.clone());
            Ok(())
        }

        async fn get(&self, id: &str) -> Result<Option<Credential>, crate::storage::StorageError> {
            let creds = self.credentials.read();
            Ok(creds.get(id).cloned())
        }

        async fn get_by_alias(
            &self,
            alias: &str,
        ) -> Result<Option<Credential>, crate::storage::StorageError> {
            let creds = self.credentials.read();
            Ok(creds.values().find(|c| c.alias == alias).cloned())
        }

        async fn list(&self) -> Result<Vec<CredentialMetadata>, crate::storage::StorageError> {
            let creds = self.credentials.read();
            Ok(creds.values().map(CredentialMetadata::from).collect())
        }

        async fn delete(&self, id: &str) -> Result<(), crate::storage::StorageError> {
            let mut creds = self.credentials.write();
            creds.remove(id);
            Ok(())
        }

        async fn update(
            &self,
            credential: &Credential,
        ) -> Result<(), crate::storage::StorageError> {
            let mut creds = self.credentials.write();
            creds.insert(credential.id.clone(), credential.clone());
            Ok(())
        }

        async fn health_check(&self) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        // Auth methods (not used in these tests)
        async fn store_role(&self, _role: &Role) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        async fn get_role(&self, _id: &str) -> Result<Option<Role>, crate::storage::StorageError> {
            Ok(None)
        }

        async fn get_role_by_name(
            &self,
            _name: &str,
        ) -> Result<Option<Role>, crate::storage::StorageError> {
            Ok(None)
        }

        async fn list_roles(&self) -> Result<Vec<Role>, crate::storage::StorageError> {
            Ok(vec![])
        }

        async fn delete_role(&self, _id: &str) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        async fn store_api_key(&self, _key: &ApiKey) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        async fn get_api_key_by_hash(
            &self,
            _hash: &str,
        ) -> Result<Option<ApiKey>, crate::storage::StorageError> {
            Ok(None)
        }

        async fn list_api_keys(&self) -> Result<Vec<ApiKey>, crate::storage::StorageError> {
            Ok(vec![])
        }

        async fn delete_api_key(&self, _id: &str) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        async fn update_api_key_last_used(
            &self,
            _id: &str,
        ) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_resolve_by_alias() {
        let storage = Arc::new(MockStorage::new());
        let cred = Credential::new(
            "github-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("test-key"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );
        storage.add(cred);

        let resolver = CredentialResolver::new(storage);
        let resolved = resolver.resolve("github-api").await.unwrap();
        assert_eq!(resolved.alias, "github-api");
    }

    #[tokio::test]
    async fn test_resolve_for_url() {
        let storage = Arc::new(MockStorage::new());
        let cred = Credential::new(
            "github-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("test-key"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );
        storage.add(cred);

        let mut resolver = CredentialResolver::new(storage);
        resolver
            .add_url_pattern("https://api.github.com/*", "github-api")
            .unwrap();

        let resolved = resolver
            .resolve_for_url("https://api.github.com/user")
            .await
            .unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().alias, "github-api");
    }
}
