//! Plugin installer
//!
//! This module handles installing plugins from various sources:
//! - Local filesystem paths
//! - Git repositories (with optional branch/tag)
//! - URLs (tar.gz archives)

use super::types::{InstalledPluginInfo, PluginManifest};
use super::PluginError;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Plugin source types
#[derive(Debug, Clone)]
pub enum PluginSource {
    /// Local filesystem path
    LocalPath(PathBuf),
    /// Git repository URL with optional ref (branch/tag/commit)
    Git {
        url: String,
        git_ref: Option<String>,
    },
    /// URL to a tar.gz archive
    Archive(String),
}

impl PluginSource {
    /// Parse a source string into a PluginSource
    pub fn parse(source: &str) -> Result<Self, PluginError> {
        let source = source.trim();

        // Check for local path
        if source.starts_with('.') || source.starts_with('/') || source.starts_with('~') {
            let expanded = shellexpand::tilde(source);
            let path = PathBuf::from(expanded.as_ref());
            return Ok(PluginSource::LocalPath(path));
        }

        // Check for git URL with optional ref
        if source.starts_with("https://github.com/")
            || source.starts_with("git@")
            || source.starts_with("https://gitlab.com/")
            || source.starts_with("https://bitbucket.org/")
        {
            // Parse ref if present (e.g., https://github.com/foo/bar#v1.0.0)
            let (url, git_ref) = if let Some(pos) = source.find('#') {
                (
                    source[..pos].to_string(),
                    Some(source[pos + 1..].to_string()),
                )
            } else {
                (source.to_string(), None)
            };

            return Ok(PluginSource::Git { url, git_ref });
        }

        // Check for archive URL
        if source.starts_with("http://") || source.starts_with("https://") {
            if source.ends_with(".tar.gz") || source.ends_with(".tgz") {
                return Ok(PluginSource::Archive(source.to_string()));
            }
            // Assume git for other https URLs
            return Ok(PluginSource::Git {
                url: source.to_string(),
                git_ref: None,
            });
        }

        // Assume local path for anything else
        Ok(PluginSource::LocalPath(PathBuf::from(source)))
    }
}

/// Plugin installer
pub struct PluginInstaller {
    /// Plugins directory (~/.vultrino/plugins)
    plugins_dir: PathBuf,
}

impl Default for PluginInstaller {
    fn default() -> Self {
        Self::new(Self::default_plugins_dir())
    }
}

impl PluginInstaller {
    /// Create a new plugin installer
    pub fn new(plugins_dir: PathBuf) -> Self {
        Self { plugins_dir }
    }

    /// Get the default plugins directory
    pub fn default_plugins_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vultrino")
            .join("plugins")
    }

    /// Ensure the plugins directory exists
    pub async fn ensure_dir(&self) -> Result<(), PluginError> {
        tokio::fs::create_dir_all(&self.plugins_dir).await?;
        Ok(())
    }

    /// Install a plugin from a source
    pub async fn install(&self, source: &str) -> Result<InstalledPluginInfo, PluginError> {
        self.ensure_dir().await?;

        let source = PluginSource::parse(source)?;
        debug!("Installing plugin from source: {:?}", source);

        // Create a temporary directory for staging
        let temp_dir = tempfile::tempdir()
            .map_err(|e| PluginError::Installation(format!("Failed to create temp dir: {}", e)))?;

        // Fetch the plugin source
        let staging_path = match &source {
            PluginSource::LocalPath(path) => self.stage_from_local(path, temp_dir.path()).await?,
            PluginSource::Git { url, git_ref } => {
                self.stage_from_git(url, git_ref.as_deref(), temp_dir.path())
                    .await?
            }
            PluginSource::Archive(url) => self.stage_from_archive(url, temp_dir.path()).await?,
        };

        // Read and validate manifest
        let manifest_path = staging_path.join("plugin.toml");
        if !manifest_path.exists() {
            return Err(PluginError::Installation(
                "No plugin.toml found in source".to_string(),
            ));
        }

        let manifest = PluginManifest::from_file(&manifest_path)?;
        let plugin_name = manifest.plugin.name.clone();

        // Check if plugin is already installed
        let target_dir = self.plugins_dir.join(&plugin_name);
        if target_dir.exists() {
            return Err(PluginError::Installation(format!(
                "Plugin '{}' is already installed. Use 'vultrino plugin remove {}' first.",
                plugin_name, plugin_name
            )));
        }

        // Build WASM if Cargo.toml exists
        if staging_path.join("Cargo.toml").exists() {
            self.build_wasm(&staging_path).await?;
        }

        // Verify WASM module exists
        if let Some(wasm_module) = manifest.wasm_module_path() {
            let wasm_path = staging_path.join(wasm_module);
            if !wasm_path.exists() {
                return Err(PluginError::Installation(format!(
                    "WASM module not found: {}. Build may have failed.",
                    wasm_module
                )));
            }
        }

        // Copy to plugins directory
        self.copy_plugin(&staging_path, &target_dir).await?;

        // Create installed info
        let installed_info = InstalledPluginInfo::new(
            manifest,
            match &source {
                PluginSource::LocalPath(p) => p.display().to_string(),
                PluginSource::Git { url, git_ref } => {
                    if let Some(r) = git_ref {
                        format!("{}#{}", url, r)
                    } else {
                        url.clone()
                    }
                }
                PluginSource::Archive(url) => url.clone(),
            },
            target_dir.clone(),
        );

        // Save installed info
        let info_path = target_dir.join(".installed.json");
        let info_json = serde_json::to_string_pretty(&installed_info)
            .map_err(|e| PluginError::Installation(format!("Failed to serialize info: {}", e)))?;
        tokio::fs::write(&info_path, info_json).await?;

        info!("Plugin '{}' installed successfully", plugin_name);
        Ok(installed_info)
    }

    /// Stage plugin from a local path
    async fn stage_from_local(&self, path: &Path, temp_dir: &Path) -> Result<PathBuf, PluginError> {
        if !path.exists() {
            return Err(PluginError::Installation(format!(
                "Path does not exist: {}",
                path.display()
            )));
        }

        // If it's a directory, copy it
        if path.is_dir() {
            let staging = temp_dir.join("plugin");
            self.copy_dir_recursive(path, &staging).await?;
            Ok(staging)
        } else {
            Err(PluginError::Installation(format!(
                "Expected directory, got file: {}",
                path.display()
            )))
        }
    }

    /// Stage plugin from a git repository
    async fn stage_from_git(
        &self,
        url: &str,
        git_ref: Option<&str>,
        temp_dir: &Path,
    ) -> Result<PathBuf, PluginError> {
        let staging = temp_dir.join("plugin");

        // Clone the repository
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg("--depth").arg("1");

        if let Some(r) = git_ref {
            cmd.arg("--branch").arg(r);
        }

        cmd.arg(url).arg(&staging);

        let output = cmd
            .output()
            .await
            .map_err(|e| PluginError::Installation(format!("Failed to run git: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PluginError::Installation(format!(
                "Git clone failed: {}",
                stderr
            )));
        }

        // Remove .git directory to save space
        let git_dir = staging.join(".git");
        if git_dir.exists() {
            tokio::fs::remove_dir_all(&git_dir).await.ok();
        }

        Ok(staging)
    }

    /// Stage plugin from a tar.gz archive URL
    async fn stage_from_archive(&self, url: &str, temp_dir: &Path) -> Result<PathBuf, PluginError> {
        // Download the archive
        let response = reqwest::get(url)
            .await
            .map_err(|e| PluginError::Installation(format!("Failed to download: {}", e)))?;

        if !response.status().is_success() {
            return Err(PluginError::Installation(format!(
                "Download failed with status: {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| PluginError::Installation(format!("Failed to read response: {}", e)))?;

        // Extract the archive
        let staging = temp_dir.join("plugin");
        tokio::fs::create_dir_all(&staging).await?;

        // Use tar command for extraction
        let archive_path = temp_dir.join("archive.tar.gz");
        tokio::fs::write(&archive_path, &bytes).await?;

        let output = Command::new("tar")
            .arg("-xzf")
            .arg(&archive_path)
            .arg("-C")
            .arg(&staging)
            .arg("--strip-components=1")
            .output()
            .await
            .map_err(|e| PluginError::Installation(format!("Failed to run tar: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PluginError::Installation(format!(
                "Tar extraction failed: {}",
                stderr
            )));
        }

        Ok(staging)
    }

    /// Build WASM module using cargo
    async fn build_wasm(&self, path: &Path) -> Result<(), PluginError> {
        info!("Building WASM module...");

        // Check if wasm target is installed
        let check_output = Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output()
            .await
            .map_err(|e| {
                PluginError::Installation(format!("Failed to check rustup targets: {}", e))
            })?;

        let targets = String::from_utf8_lossy(&check_output.stdout);
        if !targets.contains("wasm32-wasip1") {
            warn!("wasm32-wasip1 target not installed. Installing...");
            let install_output = Command::new("rustup")
                .args(["target", "add", "wasm32-wasip1"])
                .output()
                .await
                .map_err(|e| {
                    PluginError::Installation(format!("Failed to install WASM target: {}", e))
                })?;

            if !install_output.status.success() {
                let stderr = String::from_utf8_lossy(&install_output.stderr);
                return Err(PluginError::Installation(format!(
                    "Failed to install wasm32-wasip1 target: {}",
                    stderr
                )));
            }
        }

        // Build with cargo
        let output = Command::new("cargo")
            .args(["build", "--release", "--target", "wasm32-wasip1"])
            .current_dir(path)
            .output()
            .await
            .map_err(|e| PluginError::Installation(format!("Failed to run cargo: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PluginError::Installation(format!(
                "Cargo build failed: {}",
                stderr
            )));
        }

        // Copy the built .wasm file to the plugin root
        let target_dir = path.join("target/wasm32-wasip1/release");
        if target_dir.exists() {
            let mut entries = tokio::fs::read_dir(&target_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let entry_path = entry.path();
                if entry_path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    let dest = path.join(entry_path.file_name().unwrap());
                    tokio::fs::copy(&entry_path, &dest).await?;
                    info!("Built WASM module: {}", dest.display());
                    break;
                }
            }
        }

        Ok(())
    }

    /// Copy plugin files to target directory
    async fn copy_plugin(&self, source: &Path, target: &Path) -> Result<(), PluginError> {
        self.copy_dir_recursive(source, target).await
    }

    /// Recursively copy a directory
    fn copy_dir_recursive<'a>(
        &'a self,
        src: &'a Path,
        dst: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PluginError>> + Send + 'a>>
    {
        Box::pin(async move {
            tokio::fs::create_dir_all(dst).await?;

            let mut entries = tokio::fs::read_dir(src).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let dest_path = dst.join(entry.file_name());

                if path.is_dir() {
                    // Skip target directory and .git
                    let name = entry.file_name();
                    if name == "target" || name == ".git" {
                        continue;
                    }
                    self.copy_dir_recursive(&path, &dest_path).await?;
                } else {
                    tokio::fs::copy(&path, &dest_path).await?;
                }
            }

            Ok(())
        })
    }

    /// Remove an installed plugin
    pub async fn remove(&self, name: &str) -> Result<(), PluginError> {
        let plugin_dir = self.plugins_dir.join(name);

        if !plugin_dir.exists() {
            return Err(PluginError::NotFound(format!(
                "Plugin '{}' is not installed",
                name
            )));
        }

        tokio::fs::remove_dir_all(&plugin_dir).await?;
        info!("Plugin '{}' removed", name);

        Ok(())
    }

    /// List installed plugins
    pub async fn list(&self) -> Result<Vec<InstalledPluginInfo>, PluginError> {
        self.ensure_dir().await?;

        let mut plugins = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.plugins_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            if !entry.path().is_dir() {
                continue;
            }

            let info_path = entry.path().join(".installed.json");
            if info_path.exists() {
                match tokio::fs::read_to_string(&info_path).await {
                    Ok(content) => match serde_json::from_str::<InstalledPluginInfo>(&content) {
                        Ok(info) => plugins.push(info),
                        Err(e) => {
                            warn!("Failed to parse plugin info at {:?}: {}", info_path, e);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to read plugin info at {:?}: {}", info_path, e);
                    }
                }
            } else {
                // Try to load from manifest only
                let manifest_path = entry.path().join("plugin.toml");
                if manifest_path.exists() {
                    match PluginManifest::from_file(&manifest_path) {
                        Ok(manifest) => {
                            let info = InstalledPluginInfo::new(
                                manifest,
                                "unknown".to_string(),
                                entry.path(),
                            );
                            plugins.push(info);
                        }
                        Err(e) => {
                            warn!("Failed to parse manifest at {:?}: {}", manifest_path, e);
                        }
                    }
                }
            }
        }

        Ok(plugins)
    }

    /// Get plugin info
    pub async fn get(&self, name: &str) -> Result<Option<InstalledPluginInfo>, PluginError> {
        let plugin_dir = self.plugins_dir.join(name);

        if !plugin_dir.exists() {
            return Ok(None);
        }

        let info_path = plugin_dir.join(".installed.json");
        if info_path.exists() {
            let content = tokio::fs::read_to_string(&info_path).await?;
            let info = serde_json::from_str(&content)
                .map_err(|e| PluginError::Installation(format!("Failed to parse info: {}", e)))?;
            Ok(Some(info))
        } else {
            let manifest_path = plugin_dir.join("plugin.toml");
            if manifest_path.exists() {
                let manifest = PluginManifest::from_file(&manifest_path)?;
                let info = InstalledPluginInfo::new(manifest, "unknown".to_string(), plugin_dir);
                Ok(Some(info))
            } else {
                Ok(None)
            }
        }
    }

    /// Get the plugins directory
    pub fn plugins_dir(&self) -> &PathBuf {
        &self.plugins_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_path() {
        let source = PluginSource::parse("./my-plugin").unwrap();
        assert!(matches!(source, PluginSource::LocalPath(_)));

        let source = PluginSource::parse("/absolute/path").unwrap();
        assert!(matches!(source, PluginSource::LocalPath(_)));

        let source = PluginSource::parse("~/plugins/foo").unwrap();
        assert!(matches!(source, PluginSource::LocalPath(_)));
    }

    #[test]
    fn test_parse_git_url() {
        let source = PluginSource::parse("https://github.com/user/plugin").unwrap();
        assert!(matches!(
            source,
            PluginSource::Git {
                url: _,
                git_ref: None
            }
        ));

        let source = PluginSource::parse("https://github.com/user/plugin#v1.0.0").unwrap();
        if let PluginSource::Git { url, git_ref } = source {
            assert_eq!(url, "https://github.com/user/plugin");
            assert_eq!(git_ref, Some("v1.0.0".to_string()));
        } else {
            panic!("Expected Git source");
        }
    }

    #[test]
    fn test_parse_archive_url() {
        let source = PluginSource::parse("https://example.com/plugin.tar.gz").unwrap();
        assert!(matches!(source, PluginSource::Archive(_)));

        let source = PluginSource::parse("https://example.com/plugin.tgz").unwrap();
        assert!(matches!(source, PluginSource::Archive(_)));
    }
}
