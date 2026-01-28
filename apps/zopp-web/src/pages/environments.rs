use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn EnvironmentsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();
    let project = move || params.read().get("project").unwrap_or_default();

    let (environments, set_environments) = signal::<Vec<EnvironmentInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (new_env_name, set_new_env_name) = signal(String::new());
    let (creating, set_creating) = signal(false);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/import", Default::default());
        }
    });

    // Load environments on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            let ws = workspace();
            let proj = project();
            if auth_clone.is_authenticated() && !ws.is_empty() && !proj.is_empty() {
                spawn_local(async move {
                    fetch_environments(
                        auth_clone,
                        &ws,
                        &proj,
                        set_environments,
                        set_loading,
                        set_error,
                    )
                    .await;
                });
            }
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = set_environments;
        set_loading.set(false);
    }

    // Create environment handler
    let on_create = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let name = new_env_name.get();
        let ws = workspace();
        let proj = project();
        if name.is_empty() || ws.is_empty() || proj.is_empty() {
            return;
        }

        set_creating.set(true);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let name_clone = name.clone();
            let ws_clone = ws.clone();
            let proj_clone = proj.clone();
            spawn_local(async move {
                match create_environment_api(auth_clone, &ws_clone, &proj_clone, &name_clone).await
                {
                    Ok(env) => {
                        set_environments.update(|es| {
                            es.push(EnvironmentInfo {
                                id: env.id,
                                name: env.name,
                                secret_count: 0,
                            });
                        });
                        set_new_env_name.set(String::new());
                        set_show_create_modal.set(false);
                    }
                    Err(e) => {
                        set_error.set(Some(format!("Failed to create environment: {}", e)));
                    }
                }
                set_creating.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (name, ws, proj);
            set_creating.set(false);
        }
    };

    view! {
        <Layout>
            <div class="space-y-6">
                // Breadcrumb
                <nav class="breadcrumbs flex items-center gap-2 text-sm" data-testid="breadcrumb">
                    <a href=move || format!("/workspaces/{}", workspace()) class="text-cipher-secondary hover:text-cipher-text transition-colors">{workspace}</a>
                    <span class="text-cipher-muted">"/"</span>
                    <span class="text-cipher-text">{project}</span>
                </nav>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold text-cipher-text">"Environments"</h1>
                    <button
                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
                        on:click=move |_| set_show_create_modal.set(true)
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                        </svg>
                        "Create Environment"
                    </button>
                </div>

                <Show when=move || error.get().is_some()>
                    <div class="flex items-center justify-between gap-3 p-4 rounded-md text-sm border border-error-muted bg-error-muted text-error">
                        <div class="flex items-start gap-3">
                            <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>{move || error.get().unwrap_or_default()}</span>
                        </div>
                        <button class="text-sm hover:underline" on:click=move |_| set_error.set(None)>"Dismiss"</button>
                    </div>
                </Show>

                <Show when=move || loading.get()>
                    <div class="flex justify-center py-12">
                        <span class="inline-block w-8 h-8 border-4 rounded-full animate-spin border-amber/30 border-t-amber"></span>
                    </div>
                </Show>

                <Show when=move || !loading.get() && environments.get().is_empty()>
                    <div class="bg-vault-100 border border-terminal-border rounded-md">
                        <div class="p-12 flex flex-col items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-cipher-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4 text-cipher-text">"No environments yet"</h2>
                            <p class="text-cipher-secondary mt-2">
                                "Create an environment to store your secrets."
                            </p>
                            <button
                                class="inline-flex items-center justify-center gap-2 px-4 py-2 mt-6 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
                                on:click=move |_| set_show_create_modal.set(true)
                            >
                                "Create First Environment"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !environments.get().is_empty()>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <For
                            each=move || environments.get()
                            key=|e| e.id.clone()
                            children=move |env| {
                                let ws = workspace();
                                let proj = project();
                                let name = env.name.clone();
                                let display_name = env.name.clone();
                                let secret_count = env.secret_count;
                                view! {
                                    <a href=format!("/workspaces/{}/projects/{}/environments/{}", ws, proj, name) class="block bg-vault-100 border border-terminal-border rounded-md p-6 hover:border-terminal-border-strong transition-colors">
                                        <h2 class="text-lg font-semibold text-cipher-text">{display_name}</h2>
                                        <p class="text-cipher-secondary mt-1">
                                            {if secret_count == 1 {
                                                "1 secret".to_string()
                                            } else {
                                                format!("{} secrets", secret_count)
                                            }}
                                        </p>
                                    </a>
                                }
                            }
                        />
                    </div>
                </Show>

                // Create Environment Modal
                <Show when=move || show_create_modal.get()>
                    <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" on:click=move |_| set_show_create_modal.set(false)>
                        <div class="relative w-full max-w-md rounded-lg bg-vault-100 border border-terminal-border p-6" on:click=|ev| ev.stop_propagation()>
                            <h3 class="text-lg font-semibold text-cipher-text mb-4">"Create Environment"</h3>
                            <form on:submit=on_create>
                                <div class="mb-6">
                                    <div class="space-y-1.5">
                                        <label class="block text-sm font-medium text-cipher-text">"Environment Name"</label>
                                        <input
                                            type="text"
                                            placeholder="production"
                                            class="w-full px-3 py-2.5 text-sm rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                                            prop:value=move || new_env_name.get()
                                            on:input=move |ev| set_new_env_name.set(event_target_value(&ev))
                                        />
                                    </div>
                                </div>
                                <div class="flex items-center justify-end gap-3">
                                    <button
                                        type="button"
                                        class="px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-200 transition-colors"
                                        on:click=move |_| set_show_create_modal.set(false)
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        type="submit"
                                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                        disabled=move || creating.get() || new_env_name.get().is_empty()
                                    >
                                        <Show when=move || creating.get()>
                                            <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                                        </Show>
                                        "Create"
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct EnvironmentInfo {
    id: String,
    name: String,
    secret_count: usize,
}

#[cfg(target_arch = "wasm32")]
async fn fetch_environments(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    project: &str,
    set_environments: WriteSignal<Vec<EnvironmentInfo>>,
    set_loading: WriteSignal<bool>,
    set_error: WriteSignal<Option<String>>,
) {
    use zopp_proto_web::{ListEnvironmentsRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        set_loading.set(false);
        return;
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = ListEnvironmentsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
    };

    match client.list_environments(&credentials, request).await {
        Ok(response) => {
            let items: Vec<EnvironmentInfo> = response
                .environments
                .into_iter()
                .map(|e| EnvironmentInfo {
                    id: e.id,
                    name: e.name,
                    secret_count: e.secret_count as usize,
                })
                .collect();
            set_environments.set(items);
        }
        Err(e) => {
            set_error.set(Some(format!("Failed to load environments: {}", e)));
        }
    }
    set_loading.set(false);
}

#[cfg(target_arch = "wasm32")]
async fn create_environment_api(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    project: &str,
    name: &str,
) -> Result<zopp_proto_web::Environment, String> {
    use zopp_crypto::{generate_dek, public_key_from_bytes, unwrap_key, Dek, Keypair, Nonce};
    use zopp_proto_web::{
        CreateEnvironmentRequest, GetWorkspaceKeysRequest, PrincipalCredentials, ZoppWebClient,
    };

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    // 1. Fetch workspace keys to get KEK
    let keys_request = GetWorkspaceKeysRequest {
        workspace_name: workspace.to_string(),
    };
    let keys = client
        .get_workspace_keys(&credentials, keys_request)
        .await
        .map_err(|e| format!("Failed to get workspace keys: {}", e))?;

    // 2. Unwrap KEK using our x25519 private key
    let x25519_private_bytes =
        hex::decode(&creds.x25519_private_key).map_err(|e| format!("Invalid x25519 key: {}", e))?;
    let x25519_array: [u8; 32] = x25519_private_bytes
        .try_into()
        .map_err(|_| "Invalid x25519 key length")?;
    let our_keypair = Keypair::from_secret_bytes(&x25519_array);

    let ephemeral_public = public_key_from_bytes(&keys.ephemeral_pub)
        .map_err(|e| format!("Invalid ephemeral public key: {}", e))?;
    let shared_secret = our_keypair.shared_secret(&ephemeral_public);

    let mut nonce_bytes = [0u8; 24];
    if keys.kek_nonce.len() != 24 {
        return Err("Invalid KEK nonce length".to_string());
    }
    nonce_bytes.copy_from_slice(&keys.kek_nonce);
    let nonce = Nonce(nonce_bytes);

    // AAD must use workspace_id (UUID), not workspace name
    let aad = format!("workspace:{}", keys.workspace_id).into_bytes();
    let kek_bytes = unwrap_key(&keys.kek_wrapped, &nonce, &shared_secret, &aad)
        .map_err(|_| "Failed to unwrap KEK")?;

    if kek_bytes.len() != 32 {
        return Err("Invalid KEK length".to_string());
    }
    let mut kek_array = [0u8; 32];
    kek_array.copy_from_slice(&kek_bytes);
    let kek = Dek::from_bytes(&kek_array).map_err(|e| format!("Invalid KEK: {}", e))?;

    // 3. Generate new DEK for the environment
    let dek = generate_dek();

    // 4. Wrap DEK with KEK (using encrypt since KEK is symmetric)
    let dek_aad = format!("environment:{}:{}:{}", workspace, project, name).into_bytes();
    let (dek_nonce, wrapped_dek) = zopp_crypto::encrypt(dek.as_bytes(), &kek, &dek_aad)
        .map_err(|e| format!("Encrypt failed: {}", e))?;

    // 5. Create environment
    let request = CreateEnvironmentRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        name: name.to_string(),
        dek_wrapped: wrapped_dek.0,
        dek_nonce: dek_nonce.0.to_vec(),
    };

    client
        .create_environment(&credentials, request)
        .await
        .map_err(|e| e.to_string())
}
