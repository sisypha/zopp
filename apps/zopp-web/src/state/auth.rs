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

#[derive(Clone, Copy)]
pub struct AuthContext {
    principal: RwSignal<Option<Principal>>,
    loading: RwSignal<bool>,
}

impl AuthContext {
    pub fn new() -> Self {
        Self {
            principal: RwSignal::new(None),
            loading: RwSignal::new(true),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.principal.get().is_some()
    }

    pub fn is_loading(&self) -> bool {
        self.loading.get()
    }

    pub fn principal(&self) -> Option<Principal> {
        self.principal.get()
    }

    pub fn principal_name(&self) -> Option<String> {
        self.principal.get().map(|p| p.name)
    }

    pub fn set_principal(&self, principal: Option<Principal>) {
        self.principal.set(principal);
        self.loading.set(false);
    }

    pub fn logout(&self) {
        self.principal.set(None);
        // TODO: Clear IndexedDB storage
        #[cfg(target_arch = "wasm32")]
        {
            // Clear local storage and redirect
            if let Some(window) = web_sys::window() {
                if let Ok(Some(storage)) = window.local_storage() {
                    let _ = storage.remove_item("zopp_principal_id");
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
        let auth_clone = auth.clone();
        Effect::new(move || {
            spawn_local(async move {
                // TODO: Load principal from IndexedDB
                // For now, just mark as not loading
                auth_clone.loading.set(false);
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

/// Get auth context from anywhere in the component tree
pub fn use_auth() -> AuthContext {
    expect_context::<AuthContext>()
}
