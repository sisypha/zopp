use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

use crate::components::{Layout, Modal, ModalActions, ModalBody, ModalTitle};
use crate::state::auth::use_auth;
use crate::state::workspace::use_workspace;

#[component]
pub fn WorkspacesPage() -> impl IntoView {
    let auth = use_auth();
    let workspace_ctx = use_workspace();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();

    // Modal state
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (new_workspace_name, set_new_workspace_name) = signal(String::new());
    let (creating, set_creating) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/import", Default::default());
        }
    });

    // Fetch workspaces on mount
    Effect::new(move || {
        if auth.is_authenticated() {
            workspace_ctx.fetch_workspaces(auth);
        }
    });

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
            let workspace_ctx_clone = workspace_ctx;
            let name_clone = name.clone();
            spawn_local(async move {
                match create_workspace_api(auth_clone, &name_clone).await {
                    Ok(ws) => {
                        workspace_ctx_clone.add_workspace(crate::state::workspace::Workspace {
                            id: ws.id,
                            name: ws.name,
                            project_count: 0,
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
                    <h1 class="text-3xl font-bold text-cipher-text">"Workspaces"</h1>
                    <button
                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
                        on:click=move |_| set_show_create_modal.set(true)
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                        </svg>
                        "Create Workspace"
                    </button>
                </div>

                <Show when=move || error.get().is_some()>
                    <div data-testid="error-alert" class="flex items-center justify-between gap-3 p-4 rounded-md text-sm border border-error-muted bg-error-muted text-error">
                        <div class="flex items-start gap-3">
                            <svg xmlns="http://www.w3.org/2000/svg" class="shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>{move || error.get().unwrap_or_default()}</span>
                        </div>
                        <button class="text-sm hover:underline" on:click=move |_| set_error.set(None)>"Dismiss"</button>
                    </div>
                </Show>

                <Show when=move || workspace_ctx.is_loading()>
                    <div class="flex justify-center py-12">
                        <span class="inline-block w-8 h-8 border-4 rounded-full animate-spin border-amber/30 border-t-amber"></span>
                    </div>
                </Show>

                <Show when=move || !workspace_ctx.is_loading() && workspace_ctx.workspaces().is_empty()>
                    <div class="bg-vault-100 border border-terminal-border rounded-md">
                        <div class="p-12 flex flex-col items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-cipher-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4 text-cipher-text">"No workspaces yet"</h2>
                            <p class="text-cipher-secondary mt-2">
                                "Create a workspace to start organizing your secrets."
                            </p>
                            <button
                                class="inline-flex items-center justify-center gap-2 px-4 py-2 mt-4 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
                                on:click=move |_| set_show_create_modal.set(true)
                            >
                                "Create First Workspace"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !workspace_ctx.is_loading() && !workspace_ctx.workspaces().is_empty()>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <For
                            each=move || workspace_ctx.workspaces()
                            key=|ws| ws.id.clone()
                            children=move |ws| {
                                let name = ws.name.clone();
                                let display_name = ws.name.clone();
                                let project_count = ws.project_count;
                                view! {
                                    <a href=format!("/workspaces/{}", name) class="bg-vault-100 border border-terminal-border rounded-md p-6 hover:border-terminal-border-strong transition-colors">
                                        <h2 class="text-lg font-semibold text-cipher-text">{display_name}</h2>
                                        <p class="text-cipher-secondary mt-1">
                                            {if project_count == 1 {
                                                "1 project".to_string()
                                            } else {
                                                format!("{} projects", project_count)
                                            }}
                                        </p>
                                    </a>
                                }
                            }
                        />
                    </div>
                </Show>

                // Create Workspace Modal
                <Modal open=show_create_modal.into() on_close=Callback::new(move |_| set_show_create_modal.set(false)) max_width="max-w-md">
                    <ModalTitle>"Create Workspace"</ModalTitle>
                    <ModalBody>
                        <form id="create-workspace-form" on:submit=on_create class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-cipher-secondary mb-1">"Workspace Name"</label>
                                <input
                                    type="text"
                                    placeholder="my-workspace"
                                    class="w-full px-3 py-2 rounded-sm text-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:ring-2 focus:ring-control-focus"
                                    prop:value=move || new_workspace_name.get()
                                    on:input=move |ev| set_new_workspace_name.set(event_target_value(&ev))
                                />
                            </div>
                        </form>
                    </ModalBody>
                    <ModalActions>
                        <button
                            type="button"
                            class="px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-200 transition-colors"
                            on:click=move |_| set_show_create_modal.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            type="submit"
                            form="create-workspace-form"
                            class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors disabled:opacity-50"
                            disabled=move || creating.get() || new_workspace_name.get().is_empty()
                        >
                            <Show when=move || creating.get()>
                                <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                            </Show>
                            "Create"
                        </button>
                    </ModalActions>
                </Modal>
            </div>
        </Layout>
    }
}

#[cfg(target_arch = "wasm32")]
async fn create_workspace_api(
    auth: crate::state::auth::AuthContext,
    name: &str,
) -> Result<WorkspaceInfo, String> {
    use zopp_proto_web::{PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    let response = client
        .create_workspace(&credentials, name)
        .await
        .map_err(|e| format!("Failed to create workspace: {}", e))?;

    Ok(WorkspaceInfo {
        id: response.id,
        name: response.name,
    })
}

#[cfg(target_arch = "wasm32")]
struct WorkspaceInfo {
    id: String,
    name: String,
}
