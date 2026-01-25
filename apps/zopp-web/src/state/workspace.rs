use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;

#[derive(Clone, Debug, PartialEq)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub project_count: usize,
}

#[derive(Clone, Copy)]
pub struct WorkspaceContext {
    workspaces: RwSignal<Vec<Workspace>>,
    current: RwSignal<Option<Workspace>>,
    loading: RwSignal<bool>,
}

impl WorkspaceContext {
    pub fn new() -> Self {
        Self {
            workspaces: RwSignal::new(vec![]),
            current: RwSignal::new(None),
            loading: RwSignal::new(false),
        }
    }

    pub fn workspaces(&self) -> Vec<Workspace> {
        self.workspaces.get()
    }

    pub fn current(&self) -> Option<Workspace> {
        self.current.get()
    }

    pub fn current_name(&self) -> Option<String> {
        self.current.get().map(|w| w.name)
    }

    pub fn is_loading(&self) -> bool {
        self.loading.get()
    }

    pub fn set_current(&self, workspace: Option<Workspace>) {
        self.current.set(workspace.clone());
        // Persist to localStorage
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(window) = web_sys::window() {
                if let Ok(Some(storage)) = window.local_storage() {
                    if let Some(ws) = workspace {
                        let _ = storage.set_item("zopp_current_workspace", &ws.name);
                    } else {
                        let _ = storage.remove_item("zopp_current_workspace");
                    }
                }
            }
        }
    }

    pub fn set_current_by_name(&self, name: &str) {
        let workspace = self.workspaces.get().into_iter().find(|w| w.name == name);
        self.set_current(workspace);
    }

    pub fn set_workspaces(&self, workspaces: Vec<Workspace>) {
        self.workspaces.set(workspaces);
    }

    pub fn add_workspace(&self, workspace: Workspace) {
        self.workspaces.update(|ws| ws.push(workspace));
    }

    pub fn fetch_workspaces(&self, auth: crate::state::auth::AuthContext) {
        #[cfg(target_arch = "wasm32")]
        {
            let ctx = *self;
            ctx.loading.set(true);
            spawn_local(async move {
                match fetch_workspaces_api(auth).await {
                    Ok(workspaces) => {
                        ctx.workspaces.set(workspaces.clone());

                        // Restore current workspace from localStorage
                        if let Some(window) = web_sys::window() {
                            if let Ok(Some(storage)) = window.local_storage() {
                                if let Ok(Some(name)) = storage.get_item("zopp_current_workspace") {
                                    if let Some(ws) = workspaces.iter().find(|w| w.name == name) {
                                        ctx.current.set(Some(ws.clone()));
                                    } else if !workspaces.is_empty() {
                                        // Fallback to first workspace if saved one doesn't exist
                                        ctx.current.set(Some(workspaces[0].clone()));
                                    }
                                } else if !workspaces.is_empty() {
                                    // No saved workspace, use first one
                                    ctx.current.set(Some(workspaces[0].clone()));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        web_sys::console::warn_1(&format!("Failed to fetch workspaces: {}", e).into());
                    }
                }
                ctx.loading.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = auth;
            self.loading.set(false);
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_workspaces_api(
    auth: crate::state::auth::AuthContext,
) -> Result<Vec<Workspace>, String> {
    use zopp_proto_web::{PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    let response = client
        .list_workspaces(&credentials)
        .await
        .map_err(|e| format!("Failed to list workspaces: {}", e))?;

    Ok(response
        .workspaces
        .into_iter()
        .map(|w| Workspace {
            id: w.id,
            name: w.name,
            project_count: w.project_count as usize,
        })
        .collect())
}

/// Provide workspace context to the component tree
#[component]
pub fn WorkspaceProvider(children: Children) -> impl IntoView {
    let ctx = WorkspaceContext::new();
    provide_context(ctx);
    children()
}

/// Get workspace context from the component tree
pub fn use_workspace() -> WorkspaceContext {
    expect_context::<WorkspaceContext>()
}
