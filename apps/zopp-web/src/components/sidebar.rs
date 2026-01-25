use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos::web_sys;
use leptos_router::hooks::use_navigate;

use crate::components::{Avatar, AvatarSize, Modal, ModalActions, ModalBody, ModalTitle};
use crate::state::auth::use_auth;
use crate::state::workspace::use_workspace;

#[component]
pub fn Sidebar() -> impl IntoView {
    let auth = use_auth();
    let workspace_ctx = use_workspace();
    let navigate = StoredValue::new(use_navigate());
    let (user_dropdown_open, set_user_dropdown_open) = signal(false);
    let (workspace_dropdown_open, set_workspace_dropdown_open) = signal(false);
    let (show_logout_modal, set_show_logout_modal) = signal(false);
    let (show_create_workspace_modal, set_show_create_workspace_modal) = signal(false);
    let (new_workspace_name, set_new_workspace_name) = signal(String::new());
    let (creating_workspace, set_creating_workspace) = signal(false);
    let (create_error, set_create_error) = signal::<Option<String>>(None);

    let on_close_logout_modal = Callback::new(move |_| set_show_logout_modal.set(false));
    let on_close_create_modal = Callback::new(move |_| {
        set_show_create_workspace_modal.set(false);
        set_new_workspace_name.set(String::new());
        set_create_error.set(None);
    });

    // Fetch workspaces when authenticated
    Effect::new(move || {
        if auth.is_authenticated() && !auth.is_loading() {
            workspace_ctx.fetch_workspaces(auth);
        }
    });

    view! {
        <div class="flex-shrink-0 hidden lg:flex overflow-visible">
            <aside class="min-h-full flex flex-col w-60 bg-vault-100 border-r border-terminal-border overflow-visible">
                // Workspace selector at top (Resend style)
                <Show
                    when=move || auth.is_authenticated()
                    fallback=move || view! {
                        <div class="px-4 py-4 border-b border-terminal-border">
                            <a href="/" class="text-xl font-semibold font-mono text-cipher-text hover:text-amber transition-colors">
                                "zopp"
                            </a>
                        </div>
                    }
                >
                    <div class="relative border-b border-terminal-border">
                        <button
                            type="button"
                            class="flex items-center gap-3 w-full px-4 py-3 hover:bg-vault-200 transition-colors text-left focus:outline-none"
                            on:click=move |_| set_workspace_dropdown_open.update(|v| *v = !*v)
                        >
                            <div class="flex items-center justify-center w-8 h-8 rounded-md bg-amber-muted text-amber font-semibold text-sm">
                                {move || workspace_ctx.current_name().map(|n| n.chars().next().unwrap_or('W').to_uppercase().to_string()).unwrap_or_else(|| "W".to_string())}
                            </div>
                            <span class="flex-1 text-sm font-medium text-cipher-text truncate">
                                {move || workspace_ctx.current_name().unwrap_or_else(|| "Select workspace".to_string())}
                            </span>
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-cipher-muted shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l4-4 4 4m0 6l-4 4-4-4" />
                            </svg>
                        </button>

                        // Workspace dropdown
                        <Show when=move || workspace_dropdown_open.get()>
                            <div
                                class="absolute left-2 right-2 top-full mt-1 z-50 py-2 rounded-lg bg-vault-100 border border-terminal-border shadow-lg"
                            >
                                <div class="px-3 py-1.5 text-xs font-medium text-cipher-muted uppercase tracking-wide">
                                    "Workspaces"
                                </div>
                                <For
                                    each=move || workspace_ctx.workspaces()
                                    key=|ws| ws.id.clone()
                                    children=move |ws| {
                                        let ws_name = ws.name.clone();
                                        let ws_name_for_click = ws_name.clone();
                                        let ws_name_for_nav = ws_name.clone();
                                        let ws_for_check = ws.clone();
                                        let is_current = move || workspace_ctx.current().map(|c| c.id == ws_for_check.id).unwrap_or(false);

                                        view! {
                                            <button
                                                class="flex items-center gap-3 w-full px-3 py-2 text-sm hover:bg-vault-200 transition-colors text-left"
                                                on:click=move |_| {
                                                    workspace_ctx.set_current_by_name(&ws_name_for_click);
                                                    set_workspace_dropdown_open.set(false);
                                                    let nav = navigate.get_value();
                                                    nav(&format!("/workspaces/{}", ws_name_for_nav), Default::default());
                                                }
                                            >
                                                <div class="flex items-center justify-center w-7 h-7 rounded-md bg-vault-200 text-cipher-text font-medium text-xs">
                                                    {ws_name.chars().next().unwrap_or('W').to_uppercase().to_string()}
                                                </div>
                                                <span class="flex-1 text-cipher-text truncate">{ws_name.clone()}</span>
                                                <Show when=is_current>
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-amber" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                                    </svg>
                                                </Show>
                                            </button>
                                        }
                                    }
                                />

                                <div class="border-t border-terminal-border my-1"></div>

                                <button
                                    class="flex items-center gap-3 w-full px-3 py-2 text-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors text-left"
                                    on:click=move |_| {
                                        set_workspace_dropdown_open.set(false);
                                        set_show_create_workspace_modal.set(true);
                                    }
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                                    </svg>
                                    "Create Workspace"
                                </button>
                            </div>
                        </Show>
                    </div>
                </Show>

                // Navigation
                <nav class="flex flex-col gap-1 flex-1 p-2">
                    <Show when=move || auth.is_authenticated()>
                        // Projects link (shows projects for current workspace)
                        <Show when=move || workspace_ctx.current().is_some()>
                            <a
                                href=move || format!("/workspaces/{}", workspace_ctx.current_name().unwrap_or_default())
                                class="flex items-center gap-3 px-3 py-2 text-sm rounded-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                                </svg>
                                "Projects"
                            </a>
                            <a
                                href=move || format!("/workspaces/{}/permissions", workspace_ctx.current_name().unwrap_or_default())
                                class="flex items-center gap-3 px-3 py-2 text-sm rounded-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
                                </svg>
                                "Permissions"
                            </a>
                            <a
                                href=move || format!("/workspaces/{}/invites", workspace_ctx.current_name().unwrap_or_default())
                                class="flex items-center gap-3 px-3 py-2 text-sm rounded-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                                </svg>
                                "Invites"
                            </a>
                        </Show>

                        <Show when=move || workspace_ctx.current().is_none()>
                            <div class="px-3 py-4 text-sm text-cipher-muted text-center">
                                "Select a workspace to get started"
                            </div>
                        </Show>

                        <div class="flex-1"></div>

                        <a href="/settings" class="flex items-center gap-3 px-3 py-2 text-sm rounded-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                            </svg>
                            "Settings"
                        </a>
                    </Show>
                    <Show when=move || !auth.is_authenticated()>
                        <a href="/invite" class="flex items-center gap-3 px-3 py-2 text-sm rounded-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                            </svg>
                            "Join with Invite"
                        </a>
                        <a href="/import" class="flex items-center gap-3 px-3 py-2 text-sm rounded-sm text-cipher-secondary hover:bg-vault-200 hover:text-cipher-text transition-colors">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                            </svg>
                            "Import Principal"
                        </a>
                    </Show>
                </nav>

                // User menu at bottom
                <Show when=move || auth.is_authenticated()>
                    <div class="border-t border-terminal-border overflow-visible relative">
                        <button
                            type="button"
                            class="flex items-center gap-3 w-full px-4 py-4 hover:bg-vault-200 transition-colors text-left focus:outline-none"
                            on:click=move |_| set_user_dropdown_open.update(|v| *v = !*v)
                        >
                            <Avatar size=AvatarSize::Sm>
                                {move || auth.principal_name().map(|n| n.chars().next().unwrap_or('U').to_uppercase().to_string()).unwrap_or_else(|| "U".to_string())}
                            </Avatar>
                            <span class="flex-1 text-sm font-medium text-cipher-text truncate text-left">
                                {move || auth.principal_name().unwrap_or_else(|| "User".to_string())}
                            </span>
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-cipher-muted shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l4-4 4 4m0 6l-4 4-4-4" />
                            </svg>
                        </button>
                        <Show when=move || user_dropdown_open.get()>
                            <div
                                class="absolute left-2 right-2 bottom-full mb-2 z-50 py-1 rounded-lg bg-vault-100 border border-terminal-border shadow-lg"
                            >
                                <button
                                    class="flex items-center gap-3 w-full px-3 py-2.5 text-sm text-error hover:bg-error-muted transition-colors"
                                    on:click=move |_| {
                                        set_user_dropdown_open.set(false);
                                        set_show_logout_modal.set(true);
                                    }
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                    </svg>
                                    "Logout"
                                </button>
                            </div>
                        </Show>
                    </div>
                </Show>
            </aside>

            // Logout confirmation modal
            <Modal open=show_logout_modal.into() on_close=on_close_logout_modal max_width="max-w-sm">
                <ModalTitle>
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-error" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    "Logout"
                </ModalTitle>
                <ModalBody>
                    <p class="text-sm text-cipher-secondary mb-2">
                        "This will delete "<strong class="text-cipher-text">"all principals"</strong>" from this browser."
                    </p>
                    <p class="text-sm text-cipher-secondary">
                        "Make sure you have exported backups of your principals before proceeding."
                    </p>
                </ModalBody>
                <ModalActions>
                    <button
                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-100 transition-colors"
                        on:click=move |_| set_show_logout_modal.set(false)
                    >
                        "Cancel"
                    </button>
                    <button
                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-error border border-error-muted hover:bg-error-muted transition-colors"
                        on:click=move |_| {
                            set_show_logout_modal.set(false);
                            auth.logout();
                            if let Some(window) = web_sys::window() {
                                let _ = window.location().set_href("/");
                            }
                        }
                    >
                        "Delete and logout"
                    </button>
                </ModalActions>
            </Modal>

            // Create workspace modal
            <Modal open=show_create_workspace_modal.into() on_close=on_close_create_modal max_width="max-w-md">
                <ModalTitle>"Create Workspace"</ModalTitle>
                <ModalBody>
                    <Show when=move || create_error.get().is_some()>
                        <div class="flex items-start gap-3 p-4 rounded-md text-sm border border-error-muted bg-error-muted text-error mb-4">
                            <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>{move || create_error.get().unwrap_or_default()}</span>
                        </div>
                    </Show>
                    <div class="space-y-1.5">
                        <label class="block text-sm font-medium text-cipher-text">"Workspace Name"</label>
                        <input
                            type="text"
                            placeholder="my-workspace"
                            class="w-full px-3 py-2.5 text-sm rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                            prop:value=move || new_workspace_name.get()
                            on:input=move |ev| set_new_workspace_name.set(event_target_value(&ev))
                        />
                    </div>
                </ModalBody>
                <ModalActions>
                    <button
                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-100 transition-colors"
                        on:click=move |_| {
                            set_show_create_workspace_modal.set(false);
                            set_new_workspace_name.set(String::new());
                            set_create_error.set(None);
                        }
                    >
                        "Cancel"
                    </button>
                    <button
                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        disabled=move || creating_workspace.get() || new_workspace_name.get().is_empty()
                        on:click=move |_| {
                            let name = new_workspace_name.get();
                            if name.is_empty() {
                                return;
                            }
                            set_creating_workspace.set(true);
                            set_create_error.set(None);

                            #[cfg(target_arch = "wasm32")]
                            {
                                let auth_clone = auth;
                                let workspace_ctx_clone = workspace_ctx;
                                let navigate_fn = navigate.get_value();
                                spawn_local(async move {
                                    match create_workspace_api(auth_clone, &name).await {
                                        Ok(response) => {
                                            let ws = crate::state::workspace::Workspace {
                                                id: response.id,
                                                name: response.name.clone(),
                                                project_count: 0,
                                            };
                                            workspace_ctx_clone.add_workspace(ws.clone());
                                            workspace_ctx_clone.set_current(Some(ws.clone()));
                                            set_show_create_workspace_modal.set(false);
                                            set_new_workspace_name.set(String::new());
                                            // Navigate to the new workspace's projects
                                            navigate_fn(&format!("/workspaces/{}", response.name), Default::default());
                                        }
                                        Err(e) => {
                                            set_create_error.set(Some(e));
                                        }
                                    }
                                    set_creating_workspace.set(false);
                                });
                            }

                            #[cfg(not(target_arch = "wasm32"))]
                            {
                                let _ = name;
                                set_creating_workspace.set(false);
                            }
                        }
                    >
                        <Show when=move || creating_workspace.get()>
                            <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                        </Show>
                        "Create"
                    </button>
                </ModalActions>
            </Modal>
        </div>
    }
}

#[cfg(target_arch = "wasm32")]
async fn create_workspace_api(
    auth: crate::state::auth::AuthContext,
    name: &str,
) -> Result<zopp_proto_web::Workspace, String> {
    use zopp_crypto::{generate_dek, wrap_key, Keypair};
    use zopp_proto_web::{CreateWorkspaceRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    // Generate workspace KEK
    let kek = generate_dek();

    // Wrap KEK for ourselves using ECDH
    let x25519_private_bytes =
        hex::decode(&creds.x25519_private_key).map_err(|e| format!("Invalid x25519 key: {}", e))?;
    let x25519_array: [u8; 32] = x25519_private_bytes
        .try_into()
        .map_err(|_| "Invalid x25519 key length")?;
    let our_keypair = Keypair::from_secret_bytes(&x25519_array);

    // Generate ephemeral keypair for key wrapping
    let ephemeral = Keypair::generate();
    let our_public = zopp_crypto::public_key_from_bytes(&our_keypair.public_key_bytes())
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let shared_secret = ephemeral.shared_secret(&our_public);

    // Generate a UUID v4 for the workspace ID
    let id = generate_uuid();

    // AAD must use workspace_id (UUID), not workspace name
    let aad = format!("workspace:{}", id).into_bytes();
    let (nonce, wrapped) = wrap_key(kek.as_bytes(), &shared_secret, &aad)
        .map_err(|e| format!("Wrap failed: {}", e))?;

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    let request = CreateWorkspaceRequest {
        id,
        name: name.to_string(),
        ephemeral_pub: ephemeral.public_key_bytes().to_vec(),
        kek_wrapped: wrapped.0,
        kek_nonce: nonce.0.to_vec(),
    };

    client
        .create_workspace(&credentials, request)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
fn generate_uuid() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
    )
}
