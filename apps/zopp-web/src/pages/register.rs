use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

#[cfg(target_arch = "wasm32")]
use crate::services::storage::{IndexedDbStorage, KeyStorage, StoredPrincipal};
use crate::state::auth::use_auth;

/// State for pending verification
#[derive(Clone)]
#[allow(dead_code)] // Fields used conditionally in wasm32 target
struct PendingVerification {
    result: JoinResult,
    email: String,
    device_name: String,
}

#[component]
pub fn RegisterPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    // Join form state
    let (invite_token, set_invite_token) = signal(String::new());
    let (email, set_email) = signal(String::new());
    let (device_name, set_device_name) = signal(String::new());
    let (error, set_error) = signal::<Option<String>>(None);
    let (loading, set_loading) = signal(false);

    // Verification state
    let (pending_verification, set_pending_verification) =
        signal::<Option<PendingVerification>>(None);
    let (verification_code, set_verification_code) = signal(String::new());
    let (verification_error, set_verification_error) = signal::<Option<String>>(None);
    let (verification_success, set_verification_success) = signal::<Option<String>>(None);
    let (verifying, set_verifying) = signal(false);
    let (resending, set_resending) = signal(false);

    // Store auth for use in completion
    let auth_for_complete = auth;
    let _ = navigate; // Navigation handled via window.location

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let token = invite_token.get();
        let mail = email.get();
        let device = device_name.get();

        if token.is_empty() || mail.is_empty() || device.is_empty() {
            set_error.set(Some("Please fill in all fields".to_string()));
            return;
        }

        if !token.starts_with("inv_") {
            set_error.set(Some(
                "Invalid invite token format (must start with 'inv_')".to_string(),
            ));
            return;
        }

        set_loading.set(true);
        set_error.set(None);

        let auth_clone = auth_for_complete;

        spawn_local(async move {
            match join_workspace(&token, &mail, &device).await {
                Ok(result) => {
                    if result.verification_required {
                        // Need email verification - store result and show verification UI
                        set_pending_verification.set(Some(PendingVerification {
                            result,
                            email: mail,
                            device_name: device,
                        }));
                        set_loading.set(false);
                    } else {
                        // No verification needed - complete registration
                        if complete_registration_impl(
                            result,
                            mail,
                            device,
                            auth_clone,
                            set_error,
                            set_loading,
                        )
                        .await
                        {
                            // Navigate on success - use window.location for simplicity
                            #[cfg(target_arch = "wasm32")]
                            if let Some(window) = web_sys::window() {
                                let _ = window.location().set_href("/settings");
                            }
                        }
                    }
                }
                Err(e) => {
                    set_error.set(Some(format!("Join failed: {}", e)));
                    set_loading.set(false);
                }
            }
        });
    };

    let on_verify = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let code = verification_code.get();

        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            set_verification_error.set(Some("Please enter a 6-digit code".to_string()));
            return;
        }

        #[allow(unused_variables)] // Used in wasm32 target
        let pending = match pending_verification.get() {
            Some(p) => p,
            None => return,
        };

        set_verifying.set(true);
        set_verification_error.set(None);
        set_verification_success.set(None);

        let auth_clone = auth_for_complete;

        spawn_local(async move {
            #[cfg(target_arch = "wasm32")]
            {
                match verify_email_code(&pending.email, &code, &pending.result).await {
                    Ok(verify_result) => {
                        if verify_result.success {
                            // Verification successful - update result with principal_id from verify response
                            let mut updated_result = pending.result.clone();
                            updated_result.principal_id = verify_result.principal_id;
                            if let Some(user_id) = verify_result.user_id {
                                updated_result.user_id = user_id;
                            }

                            // Complete registration with updated result
                            if complete_registration_impl(
                                updated_result,
                                pending.email,
                                pending.device_name,
                                auth_clone,
                                set_verification_error,
                                set_verifying,
                            )
                            .await
                            {
                                // Navigate on success
                                if let Some(window) = web_sys::window() {
                                    let _ = window.location().set_href("/settings");
                                }
                            }
                            // Note: complete_registration_impl sets error and loading state on failure
                        } else {
                            let err_msg =
                                match (verify_result.message, verify_result.attempts_remaining) {
                                    (Some(msg), Some(attempts)) => {
                                        format!("{} ({} attempts remaining)", msg, attempts)
                                    }
                                    (Some(msg), None) => msg,
                                    (None, Some(attempts)) => {
                                        format!("Invalid code. {} attempts remaining.", attempts)
                                    }
                                    (None, None) => "Invalid verification code".to_string(),
                                };
                            set_verification_error.set(Some(err_msg));
                            set_verifying.set(false);
                        }
                    }
                    Err(e) => {
                        set_verification_error.set(Some(e));
                        set_verifying.set(false);
                    }
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = auth_clone;
                set_verification_error.set(Some("Not available on server".to_string()));
                set_verifying.set(false);
            }
        });
    };

    let on_resend = move |_| {
        #[allow(unused_variables)] // Used in wasm32 target
        let pending = match pending_verification.get() {
            Some(p) => p,
            None => return,
        };

        set_resending.set(true);
        set_verification_error.set(None);
        set_verification_success.set(None);

        spawn_local(async move {
            #[cfg(target_arch = "wasm32")]
            {
                match resend_verification_email(&pending.email, &pending.result.server_url).await {
                    Ok(msg) => {
                        set_verification_success.set(Some(msg));
                        set_resending.set(false);
                    }
                    Err(e) => {
                        set_verification_error.set(Some(e));
                        set_resending.set(false);
                    }
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                set_verification_error.set(Some("Not available on server".to_string()));
                set_resending.set(false);
            }
        });
    };

    view! {
        <div class="min-h-screen flex items-center justify-center bg-vault-base">
            <div class="bg-vault-100 border border-terminal-border rounded-md p-6 w-96">
                <div class="space-y-4">
                    <Show
                        when=move || pending_verification.get().is_some()
                        fallback=move || {
                            view! {
                                <h2 class="text-2xl font-bold text-cipher-text">"Join Workspace"</h2>
                                <p class="text-cipher-secondary text-sm">
                                    "Create a new principal using an invite token."
                                </p>

                                <form on:submit=on_submit class="space-y-4 mt-4">
                                    <Show when=move || error.get().is_some()>
                                        <div class="flex items-start gap-3 p-4 rounded-md text-sm border border-error-muted bg-error-muted text-error">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                            </svg>
                                            <span>{move || error.get().unwrap_or_default()}</span>
                                        </div>
                                    </Show>

                                    <div class="space-y-1.5">
                                        <label class="block text-sm font-medium text-cipher-text">"Invite Token"</label>
                                        <input
                                            type="text"
                                            placeholder="inv_xxxx..."
                                            class="w-full px-3 py-2.5 text-sm rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                                            prop:value=move || invite_token.get()
                                            on:input=move |ev| set_invite_token.set(event_target_value(&ev))
                                        />
                                    </div>

                                    <div class="space-y-1.5">
                                        <label class="block text-sm font-medium text-cipher-text">"Email"</label>
                                        <input
                                            type="email"
                                            placeholder="you@example.com"
                                            class="w-full px-3 py-2.5 text-sm rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                                            prop:value=move || email.get()
                                            on:input=move |ev| set_email.set(event_target_value(&ev))
                                        />
                                    </div>

                                    <div class="space-y-1.5">
                                        <label class="block text-sm font-medium text-cipher-text">"Device Name"</label>
                                        <input
                                            type="text"
                                            placeholder="My Laptop"
                                            class="w-full px-3 py-2.5 text-sm rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                                            prop:value=move || device_name.get()
                                            on:input=move |ev| set_device_name.set(event_target_value(&ev))
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        class="flex items-center justify-center gap-2 w-full px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                        disabled=move || loading.get()
                                    >
                                        <Show when=move || loading.get()>
                                            <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                                        </Show>
                                        "Create Principal"
                                    </button>
                                </form>

                                <div class="my-6 flex items-center gap-4">
                                    <div class="flex-1 border-t border-terminal-border"></div>
                                    <span class="text-cipher-muted text-sm">"or"</span>
                                    <div class="flex-1 border-t border-terminal-border"></div>
                                </div>

                                <a
                                    href="/import"
                                    class="flex items-center justify-center gap-2 w-full px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-200 transition-colors"
                                >
                                    "Import Existing Principal"
                                </a>
                            }
                        }
                    >
                        // Email verification UI
                        <h2 class="text-2xl font-bold text-cipher-text">"Verify Your Email"</h2>
                        <p class="text-cipher-secondary text-sm">
                            "We sent a verification code to "
                            <span class="font-medium">
                                {move || pending_verification.get().map(|p| p.email).unwrap_or_default()}
                            </span>
                        </p>

                        <form on:submit=on_verify class="space-y-4 mt-4">
                            <Show when=move || verification_error.get().is_some()>
                                <div class="flex items-start gap-3 p-4 rounded-md text-sm border border-error-muted bg-error-muted text-error">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    <span>{move || verification_error.get().unwrap_or_default()}</span>
                                </div>
                            </Show>

                            <Show when=move || verification_success.get().is_some()>
                                <div class="flex items-start gap-3 p-4 rounded-md text-sm border border-success-muted bg-success-muted text-success">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    <span>{move || verification_success.get().unwrap_or_default()}</span>
                                </div>
                            </Show>

                            <div class="space-y-1.5">
                                <label class="block text-sm font-medium text-cipher-text">"Verification Code"</label>
                                <input
                                    type="text"
                                    placeholder="123456"
                                    maxlength="6"
                                    class="w-full px-3 py-2.5 text-center text-2xl tracking-widest rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                                    prop:value=move || verification_code.get()
                                    on:input=move |ev| set_verification_code.set(event_target_value(&ev))
                                />
                            </div>

                            <button
                                type="submit"
                                class="flex items-center justify-center gap-2 w-full px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                disabled=move || verifying.get()
                            >
                                <Show when=move || verifying.get()>
                                    <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                                </Show>
                                "Verify Email"
                            </button>
                        </form>

                        <div class="my-6 flex items-center gap-4">
                            <div class="flex-1 border-t border-terminal-border"></div>
                            <span class="text-cipher-muted text-sm">"Didn't receive the code?"</span>
                            <div class="flex-1 border-t border-terminal-border"></div>
                        </div>

                        <button
                            type="button"
                            class="flex items-center justify-center gap-2 w-full px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                            disabled=move || resending.get()
                            on:click=on_resend
                        >
                            <Show when=move || resending.get()>
                                <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-amber/30 border-t-amber"></span>
                            </Show>
                            "Resend Code"
                        </button>

                        <button
                            type="button"
                            class="w-full px-4 py-2 mt-2 text-sm font-medium rounded-sm text-cipher-muted hover:text-cipher-text hover:bg-vault-200 transition-colors"
                            on:click=move |_| {
                                set_pending_verification.set(None);
                                set_verification_code.set(String::new());
                                set_verification_error.set(None);
                                set_verification_success.set(None);
                            }
                        >
                            "Start Over"
                        </button>
                    </Show>
                </div>
            </div>
        </div>
    }
}

/// Result of joining a workspace
#[derive(Clone)]
#[allow(dead_code)]
struct JoinResult {
    principal_id: Option<String>, // None when verification_required=true
    user_id: String,
    principal_name: String,
    ed25519_private_key: String,
    ed25519_public_key: String,
    x25519_private_key: String,
    x25519_public_key: String,
    // KEK wrapping data for workspace invites
    ephemeral_pub: Vec<u8>,
    kek_wrapped: Vec<u8>,
    kek_nonce: Vec<u8>,
    server_url: String,
    verification_required: bool,
}

/// Complete registration by storing credentials and setting auth state.
/// Returns true on success, false on failure (error will be set).
#[allow(clippy::too_many_arguments)]
async fn complete_registration_impl(
    result: JoinResult,
    mail: String,
    device: String,
    auth: crate::state::auth::AuthContext,
    set_error: WriteSignal<Option<String>>,
    set_loading: WriteSignal<bool>,
) -> bool {
    // Extract principal_id - must be present at this point
    let principal_id = match &result.principal_id {
        Some(id) => id.clone(),
        None => {
            set_error.set(Some(
                "Missing principal_id in registration result".to_string(),
            ));
            set_loading.set(false);
            return false;
        }
    };

    #[cfg(target_arch = "wasm32")]
    {
        let storage = IndexedDbStorage::new();
        let stored = StoredPrincipal {
            id: principal_id.clone(),
            name: device.clone(),
            email: Some(mail.clone()),
            user_id: Some(result.user_id.clone()),
            ed25519_private_key: result.ed25519_private_key.clone(),
            ed25519_public_key: result.ed25519_public_key.clone(),
            x25519_private_key: Some(result.x25519_private_key.clone()),
            x25519_public_key: Some(result.x25519_public_key.clone()),
            ed25519_nonce: None,
            x25519_nonce: None,
            encrypted: false,
        };
        if let Err(e) = storage.store_principal(stored).await {
            set_error.set(Some(format!("Failed to store principal: {}", e)));
            set_loading.set(false);
            return false;
        }
        if let Err(e) = storage.set_current_principal_id(Some(&principal_id)).await {
            web_sys::console::warn_1(&format!("Failed to set current principal: {}", e).into());
        }
        if let Some(window) = web_sys::window() {
            if let Ok(Some(ls)) = window.local_storage() {
                let _ = ls.set_item("zopp_server_url", &result.server_url);
            }
        }
    }

    auth.set_authenticated(
        crate::state::auth::Principal {
            id: principal_id.clone(),
            name: device.clone(),
            email: Some(mail.clone()),
            user_id: Some(result.user_id.clone()),
        },
        crate::state::auth::Credentials {
            principal_id,
            ed25519_private_key: result.ed25519_private_key,
            x25519_private_key: result.x25519_private_key,
            server_url: result.server_url,
        },
    );

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (set_error, set_loading);
    }

    true
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

        // Get server URL (handles dev vs production)
        let server_url = crate::services::config::get_server_url();
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
                ephemeral_pub: ephemeral_pub.clone(),
                kek_wrapped: kek_wrapped.clone(),
                kek_nonce: kek_nonce.clone(),
            })
            .await
            .map_err(|e| format!("Join failed: {}", e))?;

        Ok(JoinResult {
            principal_id: response.principal_id,
            user_id: response.user_id,
            principal_name: principal_name.to_string(),
            ed25519_private_key: hex::encode(signing_key.to_bytes()),
            ed25519_public_key: hex::encode(verifying_key.to_bytes()),
            x25519_private_key: hex::encode(x25519_keypair.secret_key_bytes()),
            x25519_public_key: hex::encode(x25519_keypair.public_key_bytes()),
            ephemeral_pub,
            kek_wrapped,
            kek_nonce,
            server_url,
            verification_required: response.verification_required,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (invite_code, email, principal_name);
        Err("Not available on server".to_string())
    }
}

/// Result of email verification
#[cfg(target_arch = "wasm32")]
struct VerifyResult {
    success: bool,
    message: Option<String>,
    attempts_remaining: Option<u32>,
    principal_id: Option<String>,
    user_id: Option<String>,
}

/// Verify email with a code - creates principal on success
#[cfg(target_arch = "wasm32")]
async fn verify_email_code(
    email: &str,
    code: &str,
    join_result: &JoinResult,
) -> Result<VerifyResult, String> {
    use zopp_proto_web::{VerifyEmailRequest, ZoppWebClient};

    let client = ZoppWebClient::new(&join_result.server_url);

    // Decode keys from hex for the request
    let public_key = hex::decode(&join_result.ed25519_public_key)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;
    let x25519_public_key = hex::decode(&join_result.x25519_public_key)
        .map_err(|e| format!("Invalid x25519 public key hex: {}", e))?;

    let response = client
        .verify_email(VerifyEmailRequest {
            email: email.to_string(),
            code: code.to_string(),
            principal_name: join_result.principal_name.clone(),
            public_key,
            x25519_public_key,
            ephemeral_pub: join_result.ephemeral_pub.clone(),
            kek_wrapped: join_result.kek_wrapped.clone(),
            kek_nonce: join_result.kek_nonce.clone(),
        })
        .await
        .map_err(|e| format!("Verification failed: {}", e))?;

    Ok(VerifyResult {
        success: response.success,
        message: if response.message.is_empty() {
            None
        } else {
            Some(response.message)
        },
        attempts_remaining: if response.attempts_remaining > 0 {
            Some(response.attempts_remaining as u32)
        } else {
            None
        },
        principal_id: if response.principal_id.is_empty() {
            None
        } else {
            Some(response.principal_id)
        },
        user_id: if response.user_id.is_empty() {
            None
        } else {
            Some(response.user_id)
        },
    })
}

/// Resend verification email
#[cfg(target_arch = "wasm32")]
async fn resend_verification_email(email: &str, server_url: &str) -> Result<String, String> {
    use zopp_proto_web::{ResendVerificationRequest, ZoppWebClient};

    let client = ZoppWebClient::new(server_url);
    let response = client
        .resend_verification(ResendVerificationRequest {
            email: email.to_string(),
        })
        .await
        .map_err(|e| format!("Resend failed: {}", e))?;

    if response.success {
        Ok(response.message)
    } else {
        Err(response.message)
    }
}
