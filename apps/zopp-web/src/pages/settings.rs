use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

use crate::components::{ButtonSize, ButtonVariant, Layout, LinkButton};
use crate::services::storage::PrincipalMetadata;
#[cfg(target_arch = "wasm32")]
use crate::services::storage::{IndexedDbStorage, KeyStorage};
use crate::state::auth::use_auth;

#[component]
pub fn SettingsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();
    let navigate_for_logout = navigate.clone();

    let (export_code, set_export_code) = signal::<Option<String>>(None);
    let (export_passphrase, set_export_passphrase) = signal::<Option<String>>(None);
    let (exporting, set_exporting) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (copied_code, set_copied_code) = signal(false);
    let (copied_passphrase, set_copied_passphrase) = signal(false);

    // Principal switcher state
    #[cfg(target_arch = "wasm32")]
    let (principals, set_principals) = signal::<Vec<PrincipalMetadata>>(vec![]);
    #[cfg(not(target_arch = "wasm32"))]
    let principals = signal::<Vec<PrincipalMetadata>>(vec![]).0;
    let (switching, set_switching) = signal(false);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/import", Default::default());
        }
    });

    // Load principals list
    #[cfg(target_arch = "wasm32")]
    {
        let auth_for_load = auth;
        Effect::new(move || {
            if auth_for_load.is_authenticated() {
                spawn_local(async move {
                    let storage = IndexedDbStorage::new();
                    match storage.list_principals().await {
                        Ok(list) => set_principals.set(list),
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!("Failed to load principals: {}", e).into(),
                            );
                        }
                    }
                });
            }
        });
    }

    // Switch principal handler - stored for use in For loop
    #[cfg(target_arch = "wasm32")]
    let navigate_for_switch = navigate.clone();
    let switch_principal = StoredValue::new(move |principal_id: String| {
        set_switching.set(true);
        set_error.set(None);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let navigate_clone = navigate_for_switch.clone();
            spawn_local(async move {
                match do_switch_principal(&principal_id, auth_clone).await {
                    Ok(()) => {
                        // Reload the page to refresh auth state
                        navigate_clone("/settings", Default::default());
                        // Force a full reload to ensure auth state is refreshed
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().reload();
                        }
                    }
                    Err(e) => {
                        set_error.set(Some(e));
                        set_switching.set(false);
                    }
                }
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = principal_id;
            set_switching.set(false);
        }
    });

    let on_export = move |_| {
        set_exporting.set(true);
        set_error.set(None);
        set_export_code.set(None);
        set_export_passphrase.set(None);
        set_copied_code.set(false);
        set_copied_passphrase.set(false);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            spawn_local(async move {
                match create_principal_export(auth_clone).await {
                    Ok((code, passphrase)) => {
                        set_export_code.set(Some(code));
                        set_export_passphrase.set(Some(passphrase));
                    }
                    Err(e) => {
                        set_error.set(Some(e));
                    }
                }
                set_exporting.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            set_exporting.set(false);
        }
    };

    let copy_code = move |_| {
        if let Some(code) = export_code.get() {
            #[cfg(target_arch = "wasm32")]
            {
                if let Some(window) = web_sys::window() {
                    let clipboard = window.navigator().clipboard();
                    let _ = clipboard.write_text(&code);
                    set_copied_code.set(true);
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = code;
            }
        }
    };

    let copy_passphrase = move |_| {
        if let Some(passphrase) = export_passphrase.get() {
            #[cfg(target_arch = "wasm32")]
            {
                if let Some(window) = web_sys::window() {
                    let clipboard = window.navigator().clipboard();
                    let _ = clipboard.write_text(&passphrase);
                    set_copied_passphrase.set(true);
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = passphrase;
            }
        }
    };

    let on_logout = move |_| {
        auth.logout();
        navigate_for_logout("/", Default::default());
    };

    view! {
        <Layout>
            <div class="space-y-6">
                <h1 class="text-3xl font-bold text-cipher-text">"Settings"</h1>

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

                // Current Principal Info
                <div class="bg-vault-100 border border-terminal-border rounded-md">
                    <div class="p-6">
                        <h2 class="flex items-center gap-2 text-base font-medium mb-2 text-cipher-text">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                            </svg>
                            "Current Principal"
                        </h2>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                            <div>
                                <span class="text-cipher-secondary text-sm">"Name"</span>
                                <p class="font-medium text-cipher-text">{move || auth.principal().map(|p| p.name.clone()).unwrap_or_default()}</p>
                            </div>
                            <div>
                                <span class="text-cipher-secondary text-sm">"Email"</span>
                                <p class="font-medium text-cipher-text">{move || auth.principal().and_then(|p| p.email.clone()).unwrap_or_else(|| "-".to_string())}</p>
                            </div>
                            <div class="md:col-span-2">
                                <span class="text-cipher-secondary text-sm">"Principal ID"</span>
                                <p class="font-mono text-sm break-all text-cipher-text">{move || auth.principal().map(|p| p.id.clone()).unwrap_or_default()}</p>
                            </div>
                        </div>
                    </div>
                </div>

                // Switch Principal (only show if more than one principal)
                <Show when=move || { principals.get().len() > 1 }>
                    <div class="bg-vault-100 border border-terminal-border rounded-md">
                        <div class="p-6">
                            <h2 class="flex items-center gap-2 text-base font-medium mb-2 text-cipher-text">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/>
                                </svg>
                                "Switch Principal"
                            </h2>
                            <p class="text-cipher-secondary">
                                "You have multiple principals stored. Select one to switch to."
                            </p>

                            <div class="space-y-2 mt-4">
                                <For
                                    each=move || principals.get()
                                    key=|p| p.id.clone()
                                    children=move |principal| {
                                        let principal_id = principal.id.clone();
                                        let principal_id_for_class = principal_id.clone();
                                        let principal_id_for_show = principal_id.clone();
                                        let principal_id_for_click = principal_id.clone();

                                        view! {
                                            <div class=move || {
                                                let is_current = auth.principal().map(|p| p.id == principal_id_for_class).unwrap_or(false);
                                                if is_current {
                                                    "flex items-center justify-between p-3 bg-amber-muted border border-amber rounded-lg"
                                                } else {
                                                    "flex items-center justify-between p-3 bg-vault-inset rounded-lg hover:bg-vault-200 transition-colors"
                                                }
                                            }>
                                                <div class="flex items-center gap-3">
                                                    <div class="inline-flex items-center justify-center w-10 h-10 rounded-full bg-vault-200 text-cipher-text font-medium">
                                                        <span class="text-sm">{principal.name.chars().next().unwrap_or('?').to_uppercase().to_string()}</span>
                                                    </div>
                                                    <div>
                                                        <p class="font-medium text-cipher-text">{principal.name.clone()}</p>
                                                        <p class="text-sm text-cipher-secondary">{principal.email.clone().unwrap_or_else(|| "-".to_string())}</p>
                                                    </div>
                                                </div>
                                                <Show
                                                    when=move || auth.principal().map(|p| p.id == principal_id_for_show).unwrap_or(false)
                                                    fallback=move || {
                                                        let id = principal_id_for_click.clone();
                                                        view! {
                                                            <button
                                                                class="px-3 py-1.5 text-sm font-medium rounded-sm text-cipher-secondary hover:text-cipher-text hover:bg-vault-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                                                on:click=move |_| {
                                                                    let id_clone = id.clone();
                                                                    switch_principal.with_value(|f| f(id_clone));
                                                                }
                                                                disabled=move || switching.get()
                                                            >
                                                                <Show when=move || switching.get()>
                                                                    <span class="inline-block w-3 h-3 mr-1 border-2 rounded-full animate-spin border-cipher-secondary/30 border-t-cipher-secondary"></span>
                                                                </Show>
                                                                "Switch"
                                                            </button>
                                                        }
                                                    }
                                                >
                                                    <span class="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full bg-amber-muted text-amber">"Current"</span>
                                                </Show>
                                            </div>
                                        }
                                    }
                                />
                            </div>

                            <div class="mt-4">
                                <LinkButton href="/import" variant=ButtonVariant::Secondary size=ButtonSize::Sm>
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                                    </svg>
                                    "Import Another Principal"
                                </LinkButton>
                            </div>
                        </div>
                    </div>
                </Show>

                // Export Principal
                <div class="bg-vault-100 border border-terminal-border rounded-md">
                    <div class="p-6">
                        <h2 class="flex items-center gap-2 text-base font-medium mb-2 text-cipher-text">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                            </svg>
                            "Export Principal"
                        </h2>
                        <p class="text-cipher-secondary">
                            "Export your principal to use on another device or browser. "
                            "You'll receive an export code and passphrase that can be used to import your credentials."
                        </p>

                        <Show when=move || export_code.get().is_some()>
                            <div class="flex items-start gap-3 p-4 rounded-md text-sm border border-success-muted bg-success-muted text-success mt-4">
                                <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <span>"Export created successfully!"</span>
                            </div>

                            <div class="space-y-4 mt-4">
                                <div>
                                    <label class="block text-sm font-medium text-cipher-text mb-1.5">"Export Code"</label>
                                    <div class="bg-vault-inset rounded-lg p-4">
                                        <div class="flex items-center gap-2">
                                            <code class="flex-1 font-mono text-sm break-all text-cipher-text">
                                                {move || export_code.get().unwrap_or_default()}
                                            </code>
                                            <button
                                                class="p-2 rounded-sm border border-terminal-border hover:bg-vault-200 transition-colors"
                                                on:click=copy_code
                                            >
                                                <Show
                                                    when=move || copied_code.get()
                                                    fallback=move || view! {
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-cipher-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                                        </svg>
                                                    }
                                                >
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                                    </svg>
                                                </Show>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div>
                                    <label class="block text-sm font-medium text-cipher-text mb-1.5">"Passphrase"</label>
                                    <div class="bg-vault-inset rounded-lg p-4">
                                        <div class="flex items-center gap-2">
                                            <code class="flex-1 font-mono text-sm break-all text-cipher-text">
                                                {move || export_passphrase.get().unwrap_or_default()}
                                            </code>
                                            <button
                                                class="p-2 rounded-sm border border-terminal-border hover:bg-vault-200 transition-colors"
                                                on:click=copy_passphrase
                                            >
                                                <Show
                                                    when=move || copied_passphrase.get()
                                                    fallback=move || view! {
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-cipher-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                                        </svg>
                                                    }
                                                >
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                                    </svg>
                                                </Show>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="flex items-start gap-3 p-4 rounded-md text-sm border border-warning-muted bg-warning-muted text-warning mt-4">
                                <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                <div>
                                    <span class="font-medium">"Important:"</span>
                                    <span>" This passphrase will only be shown once. Store it securely!"</span>
                                </div>
                            </div>
                        </Show>

                        <div class="flex justify-end mt-4">
                            <button
                                class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                on:click=on_export
                                disabled=move || exporting.get()
                            >
                                <Show when=move || exporting.get()>
                                    <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                                </Show>
                                "Create Export"
                            </button>
                        </div>
                    </div>
                </div>

                // Danger Zone
                <div class="bg-vault-100 border border-error-muted rounded-md">
                    <div class="p-6">
                        <h2 class="flex items-center gap-2 text-base font-medium mb-2 text-error">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                            "Danger Zone"
                        </h2>

                        <div class="flex items-center justify-between mt-4 p-4 bg-error-muted rounded-lg">
                            <div>
                                <p class="font-medium text-cipher-text">"Log out"</p>
                                <p class="text-cipher-secondary text-sm">
                                    "Clear your credentials from this browser. You can log back in with an export code."
                                </p>
                            </div>
                            <button
                                class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-error text-white hover:bg-error/90 transition-colors"
                                on:click=on_logout
                            >
                                "Log out"
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </Layout>
    }
}

#[cfg(target_arch = "wasm32")]
async fn create_principal_export(
    auth: crate::state::auth::AuthContext,
) -> Result<(String, String), String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use bip39::{Language, Mnemonic};
    use zopp_crypto::{encrypt, Dek};
    use zopp_proto_web::{CreatePrincipalExportRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let Some(principal) = auth.principal() else {
        return Err("No principal info".to_string());
    };

    // 1. Generate a random mnemonic passphrase (6 words)
    let entropy: [u8; 8] = rand::random();
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;
    let passphrase = mnemonic.words().collect::<Vec<_>>().join(" ");

    // 2. Generate salts
    let verification_salt: [u8; 16] = rand::random();
    let encryption_salt: [u8; 16] = rand::random();

    // 3. Compute token hash for server verification
    let params =
        Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| format!("Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut verification_hash = [0u8; 32];
    argon2
        .hash_password_into(
            passphrase.as_bytes(),
            &verification_salt,
            &mut verification_hash,
        )
        .map_err(|e| format!("Hash computation failed: {}", e))?;
    let token_hash_hex = hex::encode(verification_hash);

    // 4. Derive encryption key
    let mut encryption_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &encryption_salt, &mut encryption_key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    let dek = Dek::from_bytes(&encryption_key).map_err(|e| format!("Invalid DEK: {}", e))?;

    // 5. Prepare export data (principal credentials)
    let export_data = serde_json::json!({
        "principal_id": creds.principal_id,
        "principal_name": principal.name,
        "ed25519_private_key": creds.ed25519_private_key,
        "x25519_private_key": creds.x25519_private_key,
        "server_url": creds.server_url,
    });
    let export_json = serde_json::to_vec(&export_data)
        .map_err(|e| format!("Failed to serialize export: {}", e))?;

    // 6. Encrypt the export data
    let aad = b"zopp-principal-export-v2";
    let (nonce, ciphertext) =
        encrypt(&export_json, &dek, aad).map_err(|e| format!("Encryption failed: {}", e))?;

    // 7. Calculate expiration (24 hours)
    let expires_at = chrono::Utc::now().timestamp() + (24 * 3600);

    // 8. Create export on server
    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    let request = CreatePrincipalExportRequest {
        token_hash: token_hash_hex,
        verification_salt: verification_salt.to_vec(),
        encrypted_data: ciphertext.0,
        salt: encryption_salt.to_vec(),
        nonce: nonce.0.to_vec(),
        expires_at,
    };

    let response = client
        .create_principal_export(&credentials, request)
        .await
        .map_err(|e| format!("Failed to create export: {}", e))?;

    Ok((response.export_code, passphrase))
}

#[cfg(target_arch = "wasm32")]
async fn do_switch_principal(
    principal_id: &str,
    auth: crate::state::auth::AuthContext,
) -> Result<(), String> {
    use crate::services::storage::{IndexedDbStorage, KeyStorage};

    let storage = IndexedDbStorage::new();

    // Get the principal from storage
    let principal = storage
        .get_principal(principal_id)
        .await
        .map_err(|e| format!("Failed to get principal: {}", e))?
        .ok_or_else(|| "Principal not found".to_string())?;

    // Set as current principal
    storage
        .set_current_principal_id(Some(principal_id))
        .await
        .map_err(|e| format!("Failed to set current principal: {}", e))?;

    // Get server URL from localStorage
    let server_url = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|ls| ls.get_item("zopp_server_url").ok().flatten())
        .unwrap_or_else(|| crate::services::config::get_server_url());

    // Update auth state
    auth.set_authenticated(
        crate::state::auth::Principal {
            id: principal.id.clone(),
            name: principal.name.clone(),
            email: principal.email.clone(),
            user_id: principal.user_id.clone(),
        },
        crate::state::auth::Credentials {
            principal_id: principal.id,
            ed25519_private_key: principal.ed25519_private_key,
            x25519_private_key: principal.x25519_private_key.unwrap_or_default(),
            server_url,
        },
    );

    Ok(())
}
