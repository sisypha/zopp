use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;
use serde::{Deserialize, Serialize};

use crate::state::auth::use_auth;

/// Exported principal data format (matches CLI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedPrincipal {
    pub version: u32,
    pub server_url: String,
    pub email: String,
    pub user_id: String,
    pub principal: ExportedPrincipalData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedPrincipalData {
    pub id: String,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub x25519_private_key: String,
    pub x25519_public_key: String,
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_effect = navigate.clone();

    let (export_code, set_export_code) = signal(String::new());
    let (passphrase, set_passphrase) = signal(String::new());
    let (error, set_error) = signal::<Option<String>>(None);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let code = export_code.get();
        let pass = passphrase.get();

        if code.is_empty() || pass.is_empty() {
            set_error.set(Some(
                "Please enter both export code and passphrase".to_string(),
            ));
            return;
        }

        set_loading.set(true);
        set_error.set(None);

        let auth_clone = auth;
        let navigate_clone = navigate.clone();

        spawn_local(async move {
            match import_principal(&code, &pass).await {
                Ok(principal) => {
                    // Store principal in local storage for now
                    // TODO: Store in IndexedDB with encryption
                    #[cfg(target_arch = "wasm32")]
                    {
                        if let Some(window) = web_sys::window() {
                            if let Ok(Some(storage)) = window.local_storage() {
                                let _ =
                                    storage.set_item("zopp_principal_id", &principal.principal.id);
                                let _ = storage
                                    .set_item("zopp_principal_name", &principal.principal.name);
                                let _ = storage.set_item("zopp_principal_email", &principal.email);
                                let _ = storage.set_item("zopp_user_id", &principal.user_id);
                                let _ = storage.set_item(
                                    "zopp_ed25519_private",
                                    &principal.principal.private_key,
                                );
                                let _ = storage.set_item(
                                    "zopp_x25519_private",
                                    &principal.principal.x25519_private_key,
                                );
                                let _ = storage.set_item("zopp_server_url", &principal.server_url);
                            }
                        }
                    }

                    // Set auth state
                    auth_clone.set_principal(Some(crate::state::auth::Principal {
                        id: principal.principal.id,
                        name: principal.principal.name,
                        email: Some(principal.email),
                        user_id: Some(principal.user_id),
                    }));

                    // Navigate to workspaces
                    navigate_clone("/workspaces", Default::default());
                }
                Err(e) => {
                    set_error.set(Some(format!("Import failed: {}", e)));
                    set_loading.set(false);
                }
            }
        });
    };

    // Redirect if already authenticated
    Effect::new(move || {
        if auth.is_authenticated() {
            navigate_for_effect("/", Default::default());
        }
    });

    view! {
        <div class="min-h-screen flex items-center justify-center bg-base-200">
            <div class="card w-96 bg-base-100 shadow-xl">
                <div class="card-body">
                    <h2 class="card-title text-2xl font-bold text-center">"Import Principal"</h2>
                    <p class="text-base-content/70 text-sm">
                        "Enter your export code and passphrase from the CLI."
                    </p>

                    <form on:submit=on_submit class="space-y-4 mt-4">
                        <Show when=move || error.get().is_some()>
                            <div class="alert alert-error">
                                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <span>{move || error.get().unwrap_or_default()}</span>
                            </div>
                        </Show>

                        <div class="form-control">
                            <label class="label">
                                <span class="label-text">"Export Code"</span>
                            </label>
                            <input
                                type="text"
                                placeholder="Enter export code"
                                class="input input-bordered"
                                prop:value=move || export_code.get()
                                on:input=move |ev| set_export_code.set(event_target_value(&ev))
                            />
                        </div>

                        <div class="form-control">
                            <label class="label">
                                <span class="label-text">"Passphrase"</span>
                            </label>
                            <input
                                type="password"
                                placeholder="Enter passphrase"
                                class="input input-bordered"
                                prop:value=move || passphrase.get()
                                on:input=move |ev| set_passphrase.set(event_target_value(&ev))
                            />
                        </div>

                        <button
                            type="submit"
                            class="btn btn-primary w-full"
                            disabled=move || loading.get()
                        >
                            <Show when=move || loading.get()>
                                <span class="loading loading-spinner"></span>
                            </Show>
                            "Import"
                        </button>
                    </form>

                    <div class="divider">"OR"</div>

                    <a href="/register" class="btn btn-outline w-full">
                        "Create New Principal"
                    </a>
                </div>
            </div>
        </div>
    }
}

/// Import principal using the two-phase flow:
/// 1. Get verification salt from server
/// 2. Compute token hash, get encrypted data, decrypt
async fn import_principal(
    export_code: &str,
    passphrase: &str,
) -> Result<ExportedPrincipal, String> {
    #[cfg(target_arch = "wasm32")]
    {
        use argon2::Argon2;
        use zopp_crypto::{decrypt, Dek, Nonce};
        use zopp_proto_web::{
            ConsumePrincipalExportRequest, GetPrincipalExportRequest, ZoppWebClient,
        };

        let client = ZoppWebClient::new("http://localhost:8080");

        // Phase 1: Get verification salt
        let request = GetPrincipalExportRequest {
            export_code: export_code.to_string(),
            token_hash: String::new(), // Empty for phase 1
        };

        let response = client
            .get_principal_export(request)
            .await
            .map_err(|e| format!("Failed to get export: {}", e))?;

        let verification_salt = response.verification_salt;

        // Compute token hash using Argon2id (CLI compatible)
        let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
            .map_err(|e| format!("Invalid Argon2 params: {}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut hash = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &verification_salt, &mut hash)
            .map_err(|e| format!("Hash computation failed: {}", e))?;
        let token_hash = hex::encode(hash);

        // Phase 2: Get encrypted data with token_hash
        let request = GetPrincipalExportRequest {
            export_code: export_code.to_string(),
            token_hash: token_hash.clone(),
        };

        let response = client
            .get_principal_export(request)
            .await
            .map_err(|e| format!("Verification failed: {}", e))?;

        // Derive decryption key
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &response.salt, &mut key)
            .map_err(|e| format!("Key derivation failed: {}", e))?;

        let dek = Dek::from_bytes(&key).map_err(|e| format!("Invalid DEK: {}", e))?;

        let mut nonce_array = [0u8; 24];
        if response.nonce.len() != 24 {
            return Err("Invalid nonce length".to_string());
        }
        nonce_array.copy_from_slice(&response.nonce);
        let nonce = Nonce(nonce_array);

        // AAD used by CLI for principal export v2
        let aad = b"zopp-principal-export-v2";

        let plaintext = decrypt(&response.encrypted_data, &nonce, &dek, aad)
            .map_err(|_| "Decryption failed - wrong passphrase?")?;

        let json_str =
            String::from_utf8(plaintext.to_vec()).map_err(|e| format!("Invalid UTF-8: {}", e))?;

        let principal: ExportedPrincipal = serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to parse principal data: {}", e))?;

        // Mark export as consumed (one-time use)
        let consume_request = ConsumePrincipalExportRequest {
            export_code: export_code.to_string(),
            token_hash: token_hash.to_string(),
        };

        // Try to consume, but don't fail if it errors (just log)
        if let Err(e) = client.consume_principal_export(consume_request).await {
            web_sys::console::warn_1(&format!("Failed to consume export: {}", e).into());
        }

        Ok(principal)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (export_code, passphrase);
        Err("Not available on server".to_string())
    }
}
