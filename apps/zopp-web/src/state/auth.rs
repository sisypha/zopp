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
            .unwrap_or_else(|| "http://localhost:8080".to_string())
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
            if let Some(window) = web_sys::window() {
                if let Ok(Some(storage)) = window.local_storage() {
                    let _ = storage.remove_item("zopp_principal_id");
                    let _ = storage.remove_item("zopp_principal_name");
                    let _ = storage.remove_item("zopp_principal_email");
                    let _ = storage.remove_item("zopp_user_id");
                    let _ = storage.remove_item("zopp_ed25519_private");
                    let _ = storage.remove_item("zopp_x25519_private");
                    let _ = storage.remove_item("zopp_server_url");
                }
                let _ = window.location().set_href("/login");
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

    // Try to load existing principal from storage on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            spawn_local(async move {
                load_stored_credentials(auth_clone);
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

/// Load credentials from localStorage
#[cfg(target_arch = "wasm32")]
fn load_stored_credentials(auth: AuthContext) {
    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            let principal_id = storage.get_item("zopp_principal_id").ok().flatten();
            let principal_name = storage.get_item("zopp_principal_name").ok().flatten();
            let email = storage.get_item("zopp_principal_email").ok().flatten();
            let user_id = storage.get_item("zopp_user_id").ok().flatten();
            let ed25519_private = storage.get_item("zopp_ed25519_private").ok().flatten();
            let x25519_private = storage.get_item("zopp_x25519_private").ok().flatten();
            let server_url = storage
                .get_item("zopp_server_url")
                .ok()
                .flatten()
                .unwrap_or_else(|| "http://localhost:8080".to_string());

            if let (Some(id), Some(name), Some(ed25519), Some(x25519)) = (
                principal_id,
                principal_name,
                ed25519_private,
                x25519_private,
            ) {
                auth.set_authenticated(
                    Principal {
                        id: id.clone(),
                        name,
                        email,
                        user_id,
                    },
                    Credentials {
                        principal_id: id,
                        ed25519_private_key: ed25519,
                        x25519_private_key: x25519,
                        server_url,
                    },
                );
                return;
            }
        }
    }
    auth.loading.set(false);
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
