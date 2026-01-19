use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn InvitesPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();

    let (invite_code, set_invite_code) = signal::<Option<String>>(None);
    let (loading, set_loading) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (copied, set_copied) = signal(false);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/import", Default::default());
        }
    });

    let create_invite = move |_| {
        let ws = workspace();
        if ws.is_empty() {
            return;
        }

        set_loading.set(true);
        set_error.set(None);
        set_invite_code.set(None);
        set_copied.set(false);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let ws_clone = ws.clone();
            spawn_local(async move {
                match create_invite_api(auth_clone, &ws_clone).await {
                    Ok(code) => {
                        set_invite_code.set(Some(code));
                    }
                    Err(e) => {
                        set_error.set(Some(e));
                    }
                }
                set_loading.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = ws;
            set_loading.set(false);
        }
    };

    let copy_to_clipboard = move |_| {
        if let Some(code) = invite_code.get() {
            #[cfg(target_arch = "wasm32")]
            {
                if let Some(window) = web_sys::window() {
                    let clipboard = window.navigator().clipboard();
                    let _ = clipboard.write_text(&code);
                    set_copied.set(true);
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = code;
            }
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
                        <li>"Invites"</li>
                    </ul>
                </div>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Workspace Invites"</h1>
                </div>

                <div class="card bg-base-100 shadow">
                    <div class="card-body">
                        <h2 class="card-title">"Invite Team Members"</h2>
                        <p class="text-base-content/70">
                            "Create an invite link to add team members to this workspace. "
                            "Each invite can only be used once."
                        </p>

                        <Show when=move || error.get().is_some()>
                            <div class="alert alert-error mt-4">
                                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <span>{move || error.get().unwrap_or_default()}</span>
                            </div>
                        </Show>

                        <Show when=move || invite_code.get().is_some()>
                            <div class="alert alert-success mt-4">
                                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <div>
                                    <h3 class="font-bold">"Invite Created!"</h3>
                                    <p class="text-sm">"Share this code with the person you want to invite:"</p>
                                </div>
                            </div>

                            <div class="bg-base-200 rounded-lg p-4 mt-4">
                                <div class="flex items-center gap-2">
                                    <code class="flex-1 font-mono text-sm break-all">
                                        {move || invite_code.get().unwrap_or_default()}
                                    </code>
                                    <button
                                        class="btn btn-square btn-sm"
                                        on:click=copy_to_clipboard
                                    >
                                        <Show
                                            when=move || copied.get()
                                            fallback=move || view! {
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
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

                            <div class="alert alert-warning mt-4">
                                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                <span>"This code will only be shown once. Make sure to copy it now!"</span>
                            </div>
                        </Show>

                        <div class="card-actions justify-end mt-4">
                            <button
                                class="btn btn-primary"
                                on:click=create_invite
                                disabled=move || loading.get()
                            >
                                <Show when=move || loading.get()>
                                    <span class="loading loading-spinner loading-sm"></span>
                                </Show>
                                "Create Invite"
                            </button>
                        </div>
                    </div>
                </div>

                <div class="card bg-base-100 shadow">
                    <div class="card-body">
                        <h2 class="card-title">"How Invites Work"</h2>
                        <div class="space-y-4">
                            <div class="flex gap-4">
                                <div class="badge badge-primary badge-lg">"1"</div>
                                <div>
                                    <h3 class="font-medium">"Create an invite"</h3>
                                    <p class="text-base-content/70 text-sm">
                                        "Click the button above to generate a unique invite code."
                                    </p>
                                </div>
                            </div>
                            <div class="flex gap-4">
                                <div class="badge badge-primary badge-lg">"2"</div>
                                <div>
                                    <h3 class="font-medium">"Share the code"</h3>
                                    <p class="text-base-content/70 text-sm">
                                        "Send the invite code to your team member via a secure channel."
                                    </p>
                                </div>
                            </div>
                            <div class="flex gap-4">
                                <div class="badge badge-primary badge-lg">"3"</div>
                                <div>
                                    <h3 class="font-medium">"They join the workspace"</h3>
                                    <p class="text-base-content/70 text-sm">
                                        "They can use the invite code on the registration page to create their account and join this workspace."
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </Layout>
    }
}

#[cfg(target_arch = "wasm32")]
async fn create_invite_api(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use zopp_crypto::{encrypt, generate_dek, Dek, Keypair, Nonce};
    use zopp_proto_web::{
        CreateInviteRequest, GetWorkspaceKeysRequest, PrincipalCredentials, ZoppWebClient,
    };

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    // 1. Get workspace keys to unwrap KEK
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

    let ephemeral_public = zopp_crypto::public_key_from_bytes(&keys.ephemeral_pub)
        .map_err(|e| format!("Invalid ephemeral public key: {}", e))?;
    let shared_secret = our_keypair.shared_secret(&ephemeral_public);

    let mut nonce_bytes = [0u8; 24];
    if keys.kek_nonce.len() != 24 {
        return Err("Invalid KEK nonce length".to_string());
    }
    nonce_bytes.copy_from_slice(&keys.kek_nonce);
    let kek_nonce = Nonce(nonce_bytes);

    // AAD must use workspace_id (UUID), not workspace name
    let kek_aad = format!("workspace:{}", keys.workspace_id).into_bytes();
    let kek_bytes =
        zopp_crypto::unwrap_key(&keys.kek_wrapped, &kek_nonce, &shared_secret, &kek_aad)
            .map_err(|_| "Failed to unwrap KEK")?;

    if kek_bytes.len() != 32 {
        return Err("Invalid KEK length".to_string());
    }
    let mut kek_array = [0u8; 32];
    kek_array.copy_from_slice(&kek_bytes);
    let kek = Dek::from_bytes(&kek_array).map_err(|e| format!("Invalid KEK: {}", e))?;

    // 3. Generate a random 32-byte invite secret
    let invite_secret = generate_dek();
    let invite_secret_bytes = invite_secret.as_bytes();

    // 4. Compute SHA256 hash of the secret (for server lookup)
    let mut hasher = Sha256::new();
    hasher.update(invite_secret_bytes);
    let secret_hash = hasher.finalize();
    let secret_hash_hex = hex::encode(secret_hash);

    // 5. Encrypt KEK with the invite secret (use workspace_id for AAD)
    let aad = format!("invite:workspace:{}", keys.workspace_id).into_bytes();
    let (kek_enc_nonce, kek_encrypted) = encrypt(kek.as_bytes(), &invite_secret, &aad)
        .map_err(|e| format!("Encrypt failed: {}", e))?;

    // 6. Calculate expiration (24 hours from now)
    let expires_at = chrono::Utc::now().timestamp() + 86400;

    // 7. Create invite on server (use workspace_id)
    let request = CreateInviteRequest {
        workspace_ids: vec![keys.workspace_id.clone()],
        expires_at,
        token: secret_hash_hex,
        kek_encrypted: kek_encrypted.0,
        kek_nonce: kek_enc_nonce.0.to_vec(),
    };

    let _response = client
        .create_invite(&credentials, request)
        .await
        .map_err(|e| format!("Failed to create invite: {}", e))?;

    // 7. Return the invite code (secret as hex with prefix)
    Ok(format!("inv_{}", hex::encode(invite_secret_bytes)))
}
