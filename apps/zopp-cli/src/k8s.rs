use kube::Config;
use std::path::Path;

/// Load Kubernetes configuration
/// Tries kubeconfig path if provided, otherwise tries default kubeconfig, falls back to in-cluster
pub async fn load_k8s_config(
    kubeconfig_path: Option<&Path>,
    context: Option<&str>,
) -> Result<Config, Box<dyn std::error::Error>> {
    let config = if kubeconfig_path.is_some() {
        Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: context.map(String::from),
            ..Default::default()
        })
        .await?
    } else {
        match Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: context.map(String::from),
            ..Default::default()
        })
        .await
        {
            Ok(cfg) => cfg,
            Err(_) => Config::incluster()?,
        }
    };

    Ok(config)
}
