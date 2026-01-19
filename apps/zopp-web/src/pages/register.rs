use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

#[cfg(target_arch = "wasm32")]
use crate::services::storage::{IndexedDbStorage, KeyStorage, StoredPrincipal};
use crate::state::auth::use_auth;

#[component]
pub fn RegisterPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_effect = navigate.clone();

    let (invite_token, set_invite_token) = signal(String::new());
    let (email, set_email) = signal(String::new());
    let (device_name, set_device_name) = signal(String::new());
    let (error, set_error) = signal::<Option<String>>(None);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let token = invite_token.get();
        let mail = email.get();
        let device = device_name.get();

        if token.is_empty() || mail.is_empty() || device.is_empty() {
            set_error.set(Some("Please fill in all fields".to_string()));
            return;
        }

        // Validate invite token format
        if !token.starts_with("inv_") {
            set_error.set(Some(
                "Invalid invite token format (must start with 'inv_')".to_string(),
            ));
            return;
        }

        set_loading.set(true);
        set_error.set(None);

        let auth_clone = auth;
        let navigate_clone = navigate.clone();

        spawn_local(async move {
            match join_workspace(&token, &mail, &device).await {
                Ok(result) => {
                    // Store credentials in IndexedDB with encryption
                    #[cfg(target_arch = "wasm32")]
                    {
                        let storage = IndexedDbStorage::new();
                        let stored = StoredPrincipal {
                            id: result.principal_id.clone(),
                            name: device.clone(),
                            email: Some(mail.clone()),
                            user_id: Some(result.user_id.clone()),
                            ed25519_private_key: result.ed25519_private_key.clone(),
                            ed25519_public_key: result.ed25519_public_key.clone(),
                            x25519_private_key: Some(result.x25519_private_key.clone()),
                            x25519_public_key: Some(result.x25519_public_key.clone()),
                            ed25519_nonce: None,
                            x25519_nonce: None,
                            encrypted: false, // Will be encrypted by store_principal
                        };
                        if let Err(e) = storage.store_principal(stored).await {
                            set_error.set(Some(format!("Failed to store principal: {}", e)));
                            set_loading.set(false);
                            return;
                        }
                        // Set current principal
                        if let Err(e) = storage
                            .set_current_principal_id(Some(&result.principal_id))
                            .await
                        {
                            web_sys::console::warn_1(
                                &format!("Failed to set current principal: {}", e).into(),
                            );
                        }
                        // Store server URL in localStorage (not sensitive)
                        if let Some(window) = web_sys::window() {
                            if let Ok(Some(ls)) = window.local_storage() {
                                let _ = ls.set_item("zopp_server_url", &result.server_url);
                            }
                        }
                    }

                    // Set auth state with credentials
                    auth_clone.set_authenticated(
                        crate::state::auth::Principal {
                            id: result.principal_id.clone(),
                            name: device.clone(),
                            email: Some(mail.clone()),
                            user_id: Some(result.user_id.clone()),
                        },
                        crate::state::auth::Credentials {
                            principal_id: result.principal_id,
                            ed25519_private_key: result.ed25519_private_key,
                            x25519_private_key: result.x25519_private_key,
                            server_url: result.server_url,
                        },
                    );

                    // Navigate to workspaces
                    navigate_clone("/workspaces", Default::default());
                }
                Err(e) => {
                    set_error.set(Some(format!("Join failed: {}", e)));
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
                    <h2 class="card-title text-2xl font-bold">"Join Workspace"</h2>
                    <p class="text-base-content/70 text-sm">
                        "Create a new principal using an invite token."
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
                                <span class="label-text">"Invite Token"</span>
                            </label>
                            <input
                                type="text"
                                placeholder="zopp-invite-xxxx"
                                class="input input-bordered"
                                prop:value=move || invite_token.get()
                                on:input=move |ev| set_invite_token.set(event_target_value(&ev))
                            />
                        </div>

                        <div class="form-control">
                            <label class="label">
                                <span class="label-text">"Email"</span>
                            </label>
                            <input
                                type="email"
                                placeholder="you@example.com"
                                class="input input-bordered"
                                prop:value=move || email.get()
                                on:input=move |ev| set_email.set(event_target_value(&ev))
                            />
                        </div>

                        <div class="form-control">
                            <label class="label">
                                <span class="label-text">"Device Name"</span>
                            </label>
                            <input
                                type="text"
                                placeholder="My Laptop"
                                class="input input-bordered"
                                prop:value=move || device_name.get()
                                on:input=move |ev| set_device_name.set(event_target_value(&ev))
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
                            "Create Principal"
                        </button>
                    </form>

                    <div class="divider">"OR"</div>

                    <a href="/login" class="btn btn-outline w-full">
                        "Import Existing Principal"
                    </a>
                </div>
            </div>
        </div>
    }
}

/// Result of joining a workspace
#[allow(dead_code)]
struct JoinResult {
    principal_id: String,
    user_id: String,
    ed25519_private_key: String,
    ed25519_public_key: String,
    x25519_private_key: String,
    x25519_public_key: String,
    server_url: String,
}

/// Join a workspace using an invite token
async fn join_workspace(
    invite_code: &str,
    email: &str,
    principal_name: &str,
) -> Result<JoinResult, String> {
    #[cfg(target_arch = "wasm32")]
    {
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha256};
        use zopp_crypto::{decrypt, wrap_key, Dek, Keypair, Nonce};
        use zopp_proto_web::{GetInviteRequest, JoinRequest, ZoppWebClient};

        // Parse invite token
        let secret_hex = invite_code
            .strip_prefix("inv_")
            .ok_or("Invalid invite code format")?;
        let invite_secret =
            hex::decode(secret_hex).map_err(|e| format!("Invalid hex in invite code: {}", e))?;
        if invite_secret.len() != 32 {
            return Err("Invalid invite code length".to_string());
        }
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&invite_secret);

        // Generate new keypairs
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes().to_vec();

        let x25519_keypair = Keypair::generate();
        let x25519_public_bytes = x25519_keypair.public_key_bytes().to_vec();

        // Compute secret hash for server lookup
        let mut hasher = Sha256::new();
        hasher.update(secret_array);
        let secret_hash = hasher.finalize();
        let secret_hash_hex = hex::encode(secret_hash);

        // Derive server URL from current location or use default
        let server_url = web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .map(|origin| format!("{}/api", origin))
            .unwrap_or_else(|| "http://localhost:8080".to_string());
        let client = ZoppWebClient::new(&server_url);

        // Get invite info
        let invite = client
            .get_invite(GetInviteRequest {
                token: secret_hash_hex.clone(),
            })
            .await
            .map_err(|e| format!("Failed to get invite: {}", e))?;

        // Decrypt KEK using invite secret
        let (ephemeral_pub, kek_wrapped, kek_nonce) = if !invite.kek_encrypted.is_empty() {
            let dek = Dek::from_bytes(&secret_array).map_err(|e| format!("Invalid DEK: {}", e))?;

            let workspace_id = invite
                .workspace_ids
                .first()
                .ok_or("Invite has no workspace IDs")?;

            let aad = format!("invite:workspace:{}", workspace_id).into_bytes();

            let mut nonce_array = [0u8; 24];
            if invite.kek_nonce.len() != 24 {
                return Err("Invalid KEK nonce length".to_string());
            }
            nonce_array.copy_from_slice(&invite.kek_nonce);
            let nonce = Nonce(nonce_array);

            let kek_decrypted = decrypt(&invite.kek_encrypted, &nonce, &dek, &aad)
                .map_err(|_| "Failed to decrypt KEK")?;

            // Re-wrap KEK for joining principal using ECDH
            let ephemeral_keypair = Keypair::generate();
            let my_public = zopp_crypto::public_key_from_bytes(&x25519_keypair.public_key_bytes())
                .map_err(|e| format!("Invalid X25519 public key: {}", e))?;
            let shared_secret = ephemeral_keypair.shared_secret(&my_public);

            let wrap_aad = format!("workspace:{}", workspace_id).into_bytes();
            let (wrap_nonce, wrapped) = wrap_key(&kek_decrypted, &shared_secret, &wrap_aad)
                .map_err(|e| format!("Failed to wrap KEK: {}", e))?;

            (
                ephemeral_keypair.public_key_bytes().to_vec(),
                wrapped.0,
                wrap_nonce.0.to_vec(),
            )
        } else {
            (vec![], vec![], vec![])
        };

        // Call Join RPC
        let response = client
            .join(JoinRequest {
                invite_token: secret_hash_hex,
                email: email.to_string(),
                principal_name: principal_name.to_string(),
                public_key,
                x25519_public_key: x25519_public_bytes,
                ephemeral_pub,
                kek_wrapped,
                kek_nonce,
            })
            .await
            .map_err(|e| format!("Join failed: {}", e))?;

        Ok(JoinResult {
            principal_id: response.principal_id,
            user_id: response.user_id,
            ed25519_private_key: hex::encode(signing_key.to_bytes()),
            ed25519_public_key: hex::encode(verifying_key.to_bytes()),
            x25519_private_key: hex::encode(x25519_keypair.secret_key_bytes()),
            x25519_public_key: hex::encode(x25519_keypair.public_key_bytes()),
            server_url,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (invite_code, email, principal_name);
        Err("Not available on server".to_string())
    }
}
