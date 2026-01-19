use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn SecretsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();
    let project = move || params.read().get("project").unwrap_or_default();
    let environment = move || params.read().get("environment").unwrap_or_default();

    let (secrets, set_secrets) = signal::<Vec<SecretInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);
    let (show_add_modal, set_show_add_modal) = signal(false);
    let (creating, set_creating) = signal(false);

    // New secret form state
    let (new_key, set_new_key) = signal(String::new());
    let (new_value, set_new_value) = signal(String::new());

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/login", Default::default());
        }
    });

    // Load secrets on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            let ws = workspace();
            let proj = project();
            let env = environment();
            if auth_clone.is_authenticated()
                && !ws.is_empty()
                && !proj.is_empty()
                && !env.is_empty()
            {
                spawn_local(async move {
                    fetch_and_decrypt_secrets(
                        auth_clone,
                        &ws,
                        &proj,
                        &env,
                        set_secrets,
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
        let _ = set_secrets;
        set_loading.set(false);
    }

    let on_add_secret = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let key = new_key.get();
        let value = new_value.get();
        let ws = workspace();
        let proj = project();
        let env = environment();

        if key.is_empty() || ws.is_empty() || proj.is_empty() || env.is_empty() {
            return;
        }

        set_creating.set(true);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let key_clone = key.clone();
            let value_clone = value.clone();
            let ws_clone = ws.clone();
            let proj_clone = proj.clone();
            let env_clone = env.clone();
            spawn_local(async move {
                match create_secret_api(
                    auth_clone,
                    &ws_clone,
                    &proj_clone,
                    &env_clone,
                    &key_clone,
                    &value_clone,
                )
                .await
                {
                    Ok(()) => {
                        set_secrets.update(|ss| {
                            // Remove existing if updating
                            ss.retain(|s| s.key != key_clone);
                            ss.push(SecretInfo {
                                key: key_clone,
                                value: value_clone,
                            });
                        });
                        set_new_key.set(String::new());
                        set_new_value.set(String::new());
                        set_show_add_modal.set(false);
                    }
                    Err(e) => {
                        set_error.set(Some(format!("Failed to add secret: {}", e)));
                    }
                }
                set_creating.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (key, value, ws, proj, env);
            set_creating.set(false);
        }
    };

    let delete_secret = move |key: String| {
        let ws = workspace();
        let proj = project();
        let env = environment();

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            spawn_local(async move {
                match delete_secret_api(auth_clone, &ws, &proj, &env, &key).await {
                    Ok(()) => {
                        set_secrets.update(|ss| {
                            ss.retain(|s| s.key != key);
                        });
                    }
                    Err(e) => {
                        set_error.set(Some(format!("Failed to delete secret: {}", e)));
                    }
                }
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (ws, proj, env, key);
        }
    };

    view! {
        <Layout>
            <div class="space-y-6">
                // Breadcrumb
                <div class="text-sm breadcrumbs">
                    <ul>
                        <li><a href="/workspaces">"Workspaces"</a></li>
                        <li><a href=move || format!("/workspaces/{}", workspace())>{workspace}</a></li>
                        <li><a href=move || format!("/workspaces/{}/projects/{}", workspace(), project())>{project}</a></li>
                        <li>{environment}</li>
                    </ul>
                </div>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Secrets"</h1>
                    <button
                        class="btn btn-primary"
                        on:click=move |_| set_show_add_modal.set(true)
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                        </svg>
                        "Add Secret"
                    </button>
                </div>

                <Show when=move || error.get().is_some()>
                    <div class="alert alert-error">
                        <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span>{move || error.get().unwrap_or_default()}</span>
                        <button class="btn btn-ghost btn-sm" on:click=move |_| set_error.set(None)>"Dismiss"</button>
                    </div>
                </Show>

                <Show when=move || loading.get()>
                    <div class="flex justify-center py-12">
                        <span class="loading loading-spinner loading-lg"></span>
                    </div>
                </Show>

                <Show when=move || !loading.get() && secrets.get().is_empty()>
                    <div class="card bg-base-100 shadow">
                        <div class="card-body items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4">"No secrets yet"</h2>
                            <p class="text-base-content/70">
                                "Add your first secret to this environment."
                            </p>
                            <button
                                class="btn btn-primary mt-4"
                                on:click=move |_| set_show_add_modal.set(true)
                            >
                                "Add First Secret"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !secrets.get().is_empty()>
                    <div class="overflow-x-auto">
                        <table class="table bg-base-100">
                            <thead>
                                <tr>
                                    <th>"Key"</th>
                                    <th>"Value"</th>
                                    <th>"Actions"</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For
                                    each=move || secrets.get()
                                    key=|s| s.key.clone()
                                    children=move |secret| {
                                        let key = secret.key.clone();
                                        let value = secret.value.clone();
                                        let key_for_delete = key.clone();
                                        let (show_value, set_show_value) = signal(false);
                                        view! {
                                            <tr>
                                                <td class="font-mono">{key}</td>
                                                <td>
                                                    <Show when=move || show_value.get() fallback=move || view! { <span class="text-base-content/50">"********"</span> }>
                                                        <span class="font-mono">{value.clone()}</span>
                                                    </Show>
                                                </td>
                                                <td>
                                                    <div class="flex gap-2">
                                                        <button
                                                            class="btn btn-ghost btn-sm"
                                                            on:click=move |_| set_show_value.update(|v| *v = !*v)
                                                        >
                                                            <Show when=move || show_value.get() fallback=move || view! {
                                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                                                                </svg>
                                                            }>
                                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                                                                </svg>
                                                            </Show>
                                                        </button>
                                                        <button
                                                            class="btn btn-ghost btn-sm btn-error"
                                                            on:click={
                                                                let key = key_for_delete.clone();
                                                                move |_| delete_secret(key.clone())
                                                            }
                                                        >
                                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                                            </svg>
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        }
                                    }
                                />
                            </tbody>
                        </table>
                    </div>
                </Show>

                // Add Secret Modal
                <Show when=move || show_add_modal.get()>
                    <div class="modal modal-open">
                        <div class="modal-box">
                            <h3 class="font-bold text-lg">"Add Secret"</h3>
                            <form on:submit=on_add_secret class="space-y-4 mt-4">
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Key"</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="DATABASE_URL"
                                        class="input input-bordered font-mono"
                                        prop:value=move || new_key.get()
                                        on:input=move |ev| set_new_key.set(event_target_value(&ev))
                                    />
                                </div>
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Value"</span>
                                    </label>
                                    <textarea
                                        placeholder="Enter secret value"
                                        class="textarea textarea-bordered font-mono"
                                        rows="3"
                                        prop:value=move || new_value.get()
                                        on:input=move |ev| set_new_value.set(event_target_value(&ev))
                                    ></textarea>
                                </div>
                                <div class="modal-action">
                                    <button
                                        type="button"
                                        class="btn"
                                        on:click=move |_| set_show_add_modal.set(false)
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        type="submit"
                                        class="btn btn-primary"
                                        disabled=move || creating.get() || new_key.get().is_empty()
                                    >
                                        <Show when=move || creating.get()>
                                            <span class="loading loading-spinner loading-sm"></span>
                                        </Show>
                                        "Add Secret"
                                    </button>
                                </div>
                            </form>
                        </div>
                        <div class="modal-backdrop" on:click=move |_| set_show_add_modal.set(false)></div>
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct SecretInfo {
    key: String,
    value: String,
}

/// Get the DEK for an environment (unwrapped)
#[cfg(target_arch = "wasm32")]
async fn get_environment_dek(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<zopp_crypto::Dek, String> {
    use zopp_crypto::{public_key_from_bytes, unwrap_key, Dek, Keypair, Nonce};
    use zopp_proto_web::{
        GetWorkspaceKeysRequest, ListEnvironmentsRequest, PrincipalCredentials, ZoppWebClient,
    };

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    // 1. Get workspace keys (KEK)
    let keys_request = GetWorkspaceKeysRequest {
        workspace_name: workspace.to_string(),
    };
    let keys = client
        .get_workspace_keys(&credentials, keys_request)
        .await
        .map_err(|e| format!("Failed to get workspace keys: {}", e))?;

    // 2. Unwrap KEK
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
    let kek_nonce = Nonce(nonce_bytes);

    let kek_aad = format!("workspace:{}", workspace).into_bytes();
    let kek_bytes = unwrap_key(&keys.kek_wrapped, &kek_nonce, &shared_secret, &kek_aad)
        .map_err(|_| "Failed to unwrap KEK")?;

    if kek_bytes.len() != 32 {
        return Err("Invalid KEK length".to_string());
    }
    let mut kek_array = [0u8; 32];
    kek_array.copy_from_slice(&kek_bytes);
    let kek = Dek::from_bytes(&kek_array).map_err(|e| format!("Invalid KEK: {}", e))?;

    // 3. Get environment DEK
    let env_request = ListEnvironmentsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
    };
    let envs = client
        .list_environments(&credentials, env_request)
        .await
        .map_err(|e| format!("Failed to list environments: {}", e))?;

    let env = envs
        .environments
        .into_iter()
        .find(|e| e.name == environment)
        .ok_or_else(|| format!("Environment '{}' not found", environment))?;

    // 4. Unwrap DEK with KEK
    let mut dek_nonce_bytes = [0u8; 24];
    if env.dek_nonce.len() != 24 {
        return Err("Invalid DEK nonce length".to_string());
    }
    dek_nonce_bytes.copy_from_slice(&env.dek_nonce);
    let dek_nonce = Nonce(dek_nonce_bytes);

    let dek_aad = format!("environment:{}:{}:{}", workspace, project, environment).into_bytes();
    let dek_bytes = zopp_crypto::decrypt(&env.dek_wrapped, &dek_nonce, &kek, &dek_aad)
        .map_err(|_| "Failed to unwrap DEK")?;

    if dek_bytes.len() != 32 {
        return Err("Invalid DEK length".to_string());
    }
    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(&dek_bytes);
    Dek::from_bytes(&dek_array).map_err(|e| format!("Invalid DEK: {}", e))
}

#[cfg(target_arch = "wasm32")]
async fn fetch_and_decrypt_secrets(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    project: &str,
    environment: &str,
    set_secrets: WriteSignal<Vec<SecretInfo>>,
    set_loading: WriteSignal<bool>,
    set_error: WriteSignal<Option<String>>,
) {
    use zopp_crypto::{decrypt, Nonce};
    use zopp_proto_web::{ListSecretsRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        set_loading.set(false);
        return;
    };

    // Get DEK first
    let dek = match get_environment_dek(auth, workspace, project, environment).await {
        Ok(d) => d,
        Err(e) => {
            set_error.set(Some(e));
            set_loading.set(false);
            return;
        }
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = ListSecretsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    };

    match client.list_secrets(&credentials, request).await {
        Ok(response) => {
            let mut items = Vec::new();
            for secret in response.secrets {
                // Decrypt each secret value
                let mut nonce_bytes = [0u8; 24];
                if secret.nonce.len() != 24 {
                    continue;
                }
                nonce_bytes.copy_from_slice(&secret.nonce);
                let nonce = Nonce(nonce_bytes);

                let aad = format!(
                    "secret:{}:{}:{}:{}",
                    workspace, project, environment, secret.key
                )
                .into_bytes();

                match decrypt(&secret.ciphertext, &nonce, &dek, &aad) {
                    Ok(plaintext) => {
                        if let Ok(value) = String::from_utf8(plaintext.to_vec()) {
                            items.push(SecretInfo {
                                key: secret.key,
                                value,
                            });
                        }
                    }
                    Err(_) => {
                        // Skip secrets that fail to decrypt
                        continue;
                    }
                }
            }
            set_secrets.set(items);
        }
        Err(e) => {
            set_error.set(Some(format!("Failed to load secrets: {}", e)));
        }
    }
    set_loading.set(false);
}

#[cfg(target_arch = "wasm32")]
async fn create_secret_api(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    project: &str,
    environment: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    use zopp_crypto::encrypt;
    use zopp_proto_web::{PrincipalCredentials, UpsertSecretRequest, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    // Get DEK
    let dek = get_environment_dek(auth, workspace, project, environment).await?;

    // Encrypt the secret value
    let aad = format!("secret:{}:{}:{}:{}", workspace, project, environment, key).into_bytes();
    let (nonce, ciphertext) =
        encrypt(value.as_bytes(), &dek, &aad).map_err(|e| format!("Encryption failed: {}", e))?;

    let client = ZoppWebClient::new(&creds.server_url);
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = UpsertSecretRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        key: key.to_string(),
        nonce: nonce.0.to_vec(),
        ciphertext: ciphertext.0,
    };

    client
        .upsert_secret(&credentials, request)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn delete_secret_api(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    project: &str,
    environment: &str,
    key: &str,
) -> Result<(), String> {
    use zopp_proto_web::{DeleteSecretRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = DeleteSecretRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        key: key.to_string(),
    };

    client
        .delete_secret(&credentials, request)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
