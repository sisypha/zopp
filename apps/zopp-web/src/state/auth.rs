use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;

#[derive(Clone, Debug)]
pub struct Principal {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub user_id: Option<String>,
}

/// Credentials needed for authenticated API calls
#[derive(Clone, Debug)]
pub struct Credentials {
    pub principal_id: String,
    pub ed25519_private_key: String,
    pub x25519_private_key: String,
    pub server_url: String,
}

#[derive(Clone, Copy)]
pub struct AuthContext {
    principal: RwSignal<Option<Principal>>,
    credentials: RwSignal<Option<Credentials>>,
    loading: RwSignal<bool>,
}

impl AuthContext {
    pub fn new() -> Self {
        Self {
            principal: RwSignal::new(None),
            credentials: RwSignal::new(None),
            loading: RwSignal::new(true),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.principal.get().is_some() && self.credentials.get().is_some()
    }

    pub fn is_loading(&self) -> bool {
        self.loading.get()
    }

    pub fn principal(&self) -> Option<Principal> {
        self.principal.get()
    }

    pub fn credentials(&self) -> Option<Credentials> {
        self.credentials.get()
    }

    pub fn principal_name(&self) -> Option<String> {
        self.principal.get().map(|p| p.name)
    }

    pub fn server_url(&self) -> String {
        self.credentials
            .get()
            .map(|c| c.server_url)
            .unwrap_or_else(crate::services::config::get_server_url)
    }

    pub fn set_principal(&self, principal: Option<Principal>) {
        self.principal.set(principal);
        self.loading.set(false);
    }

    pub fn set_credentials(&self, credentials: Option<Credentials>) {
        self.credentials.set(credentials);
    }

    pub fn set_authenticated(&self, principal: Principal, credentials: Credentials) {
        self.principal.set(Some(principal));
        self.credentials.set(Some(credentials));
        self.loading.set(false);
    }

    pub fn logout(&self) {
        self.principal.set(None);
        self.credentials.set(None);
        #[cfg(target_arch = "wasm32")]
        {
            use crate::services::storage::{IndexedDbStorage, KeyStorage};

            // Clear current principal in IndexedDB
            spawn_local(async move {
                let storage = IndexedDbStorage::new();
                if let Err(e) = storage.set_current_principal_id(None).await {
                    web_sys::console::warn_1(
                        &format!("Failed to clear current principal: {}", e).into(),
                    );
                }
            });

            // Clear server URL from localStorage and redirect
            if let Some(window) = web_sys::window() {
                if let Ok(Some(storage)) = window.local_storage() {
                    let _ = storage.remove_item("zopp_server_url");
                }
                let _ = window.location().set_href("/");
            }
        }
    }
}

impl Default for AuthContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Provide auth context to the application
#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let auth = AuthContext::new();

    // Try to load existing principal from IndexedDB on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            spawn_local(async move {
                load_stored_credentials(auth_clone).await;
            });
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        auth.loading.set(false);
    }

    provide_context(auth);

    children()
}

/// Load credentials from IndexedDB
#[cfg(target_arch = "wasm32")]
async fn load_stored_credentials(auth: AuthContext) {
    use crate::services::storage::{IndexedDbStorage, KeyStorage};

    let storage = IndexedDbStorage::new();

    // Get current principal ID
    let current_id = match storage.get_current_principal_id().await {
        Ok(Some(id)) => id,
        Ok(None) => {
            auth.loading.set(false);
            return;
        }
        Err(e) => {
            web_sys::console::warn_1(&format!("Failed to get current principal: {}", e).into());
            auth.loading.set(false);
            return;
        }
    };

    // Load principal from IndexedDB
    match storage.get_principal(&current_id).await {
        Ok(Some(stored)) => {
            // Get server URL from localStorage (non-sensitive)
            let server_url = web_sys::window()
                .and_then(|w| w.local_storage().ok().flatten())
                .and_then(|s| s.get_item("zopp_server_url").ok().flatten())
                .unwrap_or_else(crate::services::config::get_server_url);

            let x25519_private = stored.x25519_private_key.unwrap_or_default();

            auth.set_authenticated(
                Principal {
                    id: stored.id.clone(),
                    name: stored.name,
                    email: stored.email,
                    user_id: stored.user_id,
                },
                Credentials {
                    principal_id: stored.id,
                    ed25519_private_key: stored.ed25519_private_key,
                    x25519_private_key: x25519_private,
                    server_url,
                },
            );
        }
        Ok(None) => {
            web_sys::console::log_1(&"No stored principal found".into());
            auth.loading.set(false);
        }
        Err(e) => {
            web_sys::console::warn_1(&format!("Failed to load principal: {}", e).into());
            auth.loading.set(false);
        }
    }
}

/// Get auth context from anywhere in the component tree
pub fn use_auth() -> AuthContext {
    expect_context::<AuthContext>()
}

/// Get credentials for API calls, or None if not authenticated
#[cfg(target_arch = "wasm32")]
pub fn use_api_credentials() -> Option<zopp_proto_web::PrincipalCredentials> {
    let auth = use_auth();
    auth.credentials()
        .map(|c| zopp_proto_web::PrincipalCredentials {
            principal_id: c.principal_id,
            ed25519_private_key: c.ed25519_private_key,
        })
}
