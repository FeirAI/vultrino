//! Plugin loader
//!
//! This module handles loading installed plugins into the plugin registry.

use super::installer::PluginInstaller;
use super::wasm::WasmPlugin;
use super::{Plugin, PluginError, PluginRegistry};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Plugin loader that loads installed plugins into a registry
pub struct PluginLoader {
    installer: PluginInstaller,
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new(PluginInstaller::default())
    }
}

impl PluginLoader {
    /// Create a new plugin loader
    pub fn new(installer: PluginInstaller) -> Self {
        Self { installer }
    }

    /// Load all installed plugins into a registry
    pub async fn load_all(&self, registry: &PluginRegistry) -> Result<usize, PluginError> {
        let installed = self.installer.list().await?;
        let mut loaded = 0;

        for info in installed {
            if !info.enabled {
                debug!("Skipping disabled plugin: {}", info.manifest.plugin.name);
                continue;
            }

            match self.load_plugin(&info.directory).await {
                Ok(plugin) => {
                    info!("Loaded plugin: {} v{}", plugin.name(), plugin.version());
                    registry.register(plugin);
                    loaded += 1;
                }
                Err(e) => {
                    warn!("Failed to load plugin {}: {}", info.manifest.plugin.name, e);
                }
            }
        }

        Ok(loaded)
    }

    /// Load a single plugin from a directory
    pub async fn load_plugin(
        &self,
        directory: &std::path::Path,
    ) -> Result<Arc<dyn Plugin>, PluginError> {
        let plugin = WasmPlugin::from_directory(directory.to_path_buf())?;
        Ok(Arc::new(plugin))
    }

    /// Reload a specific plugin by name
    pub async fn reload(&self, name: &str, registry: &PluginRegistry) -> Result<(), PluginError> {
        // Get plugin info
        let info = self
            .installer
            .get(name)
            .await?
            .ok_or_else(|| PluginError::NotFound(format!("Plugin '{}' not found", name)))?;

        // Unregister old plugin
        registry.unregister(name);

        // Load and register new plugin
        let plugin = self.load_plugin(&info.directory).await?;
        registry.register(plugin);

        info!("Reloaded plugin: {}", name);
        Ok(())
    }

    /// Get the installer
    pub fn installer(&self) -> &PluginInstaller {
        &self.installer
    }
}

/// Extension trait for PluginRegistry to integrate with loader
pub trait PluginRegistryExt {
    /// Load all installed plugins
    fn load_installed_plugins(
        &self,
    ) -> impl std::future::Future<Output = Result<usize, PluginError>> + Send;
}

impl PluginRegistryExt for PluginRegistry {
    async fn load_installed_plugins(&self) -> Result<usize, PluginError> {
        let loader = PluginLoader::default();
        loader.load_all(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_loader_creation() {
        let loader = PluginLoader::default();
        assert!(loader.installer().plugins_dir().ends_with("plugins"));
    }
}
