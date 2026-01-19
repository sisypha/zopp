use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn WorkspacesPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();

    let (workspaces, set_workspaces) = signal::<Vec<WorkspaceInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (new_workspace_name, set_new_workspace_name) = signal(String::new());
    let (creating, set_creating) = signal(false);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/import", Default::default());
        }
    });

    // Load workspaces on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            if auth_clone.is_authenticated() {
                spawn_local(async move {
                    fetch_workspaces(auth_clone, set_workspaces, set_loading, set_error).await;
                });
            }
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = set_workspaces;
        set_loading.set(false);
    }

    // Create workspace handler
    let on_create = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let name = new_workspace_name.get();
        if name.is_empty() {
            return;
        }

        set_creating.set(true);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let name_clone = name.clone();
            spawn_local(async move {
                match create_workspace_api(auth_clone, &name_clone).await {
                    Ok(workspace) => {
                        set_workspaces.update(|ws| {
                            ws.push(WorkspaceInfo {
                                id: workspace.id,
                                name: workspace.name,
                                project_count: 0,
                            });
                        });
                        set_new_workspace_name.set(String::new());
                        set_show_create_modal.set(false);
                    }
                    Err(e) => {
                        set_error.set(Some(format!("Failed to create workspace: {}", e)));
                    }
                }
                set_creating.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = name;
            set_creating.set(false);
        }
    };

    view! {
        <Layout>
            <div class="space-y-6">
                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Workspaces"</h1>
                    <button
                        class="btn btn-primary"
                        on:click=move |_| set_show_create_modal.set(true)
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                        </svg>
                        "Create Workspace"
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

                <Show when=move || !loading.get() && workspaces.get().is_empty()>
                    <div class="card bg-base-100 shadow">
                        <div class="card-body items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4">"No workspaces yet"</h2>
                            <p class="text-base-content/70">
                                "Create a workspace to start managing your secrets."
                            </p>
                            <button
                                class="btn btn-primary mt-4"
                                on:click=move |_| set_show_create_modal.set(true)
                            >
                                "Create First Workspace"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !workspaces.get().is_empty()>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <For
                            each=move || workspaces.get()
                            key=|ws| ws.id.clone()
                            children=move |ws| {
                                let name = ws.name.clone();
                                let display_name = ws.name.clone();
                                let project_count = ws.project_count;
                                view! {
                                    <a href=format!("/workspaces/{}", name) class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                                        <div class="card-body">
                                            <h2 class="card-title">{display_name}</h2>
                                            <p class="text-base-content/70">
                                                {if project_count == 1 {
                                                    "1 project".to_string()
                                                } else {
                                                    format!("{} projects", project_count)
                                                }}
                                            </p>
                                        </div>
                                    </a>
                                }
                            }
                        />
                    </div>
                </Show>

                // Create Workspace Modal
                <Show when=move || show_create_modal.get()>
                    <div class="modal modal-open">
                        <div class="modal-box">
                            <h3 class="font-bold text-lg mb-4">"Create Workspace"</h3>
                            <form on:submit=on_create>
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Workspace Name"</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="my-workspace"
                                        class="input input-bordered"
                                        prop:value=move || new_workspace_name.get()
                                        on:input=move |ev| set_new_workspace_name.set(event_target_value(&ev))
                                    />
                                </div>
                                <div class="modal-action">
                                    <button
                                        type="button"
                                        class="btn"
                                        on:click=move |_| set_show_create_modal.set(false)
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        type="submit"
                                        class="btn btn-primary"
                                        disabled=move || creating.get() || new_workspace_name.get().is_empty()
                                    >
                                        <Show when=move || creating.get()>
                                            <span class="loading loading-spinner loading-sm"></span>
                                        </Show>
                                        "Create"
                                    </button>
                                </div>
                            </form>
                        </div>
                        <div class="modal-backdrop" on:click=move |_| set_show_create_modal.set(false)></div>
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct WorkspaceInfo {
    id: String,
    name: String,
    project_count: usize,
}

#[cfg(target_arch = "wasm32")]
async fn fetch_workspaces(
    auth: crate::state::auth::AuthContext,
    set_workspaces: WriteSignal<Vec<WorkspaceInfo>>,
    set_loading: WriteSignal<bool>,
    set_error: WriteSignal<Option<String>>,
) {
    use zopp_proto_web::{PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        set_loading.set(false);
        return;
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    match client.list_workspaces(&credentials).await {
        Ok(response) => {
            let items: Vec<WorkspaceInfo> = response
                .workspaces
                .into_iter()
                .map(|w| WorkspaceInfo {
                    id: w.id,
                    name: w.name,
                    project_count: w.project_count as usize,
                })
                .collect();
            set_workspaces.set(items);
        }
        Err(e) => {
            set_error.set(Some(format!("Failed to load workspaces: {}", e)));
        }
    }
    set_loading.set(false);
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

    // Generate a UUID v4 for the workspace ID (v7 requires timestamp which is more complex)
    // Must generate ID first since it's used in AAD for key wrapping
    let id = generate_uuid();

    // AAD must use workspace_id (UUID), not workspace name - must match unwrap AAD
    let aad = format!("workspace:{}", id).into_bytes();
    let (nonce, wrapped) = wrap_key(kek.as_bytes(), &shared_secret, &aad)
        .map_err(|e| format!("Wrap failed: {}", e))?;

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
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
    // Generate a UUID v4 using random bytes
    let mut bytes: [u8; 16] = rand::random();
    // Set version 4
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ])
    )
}
