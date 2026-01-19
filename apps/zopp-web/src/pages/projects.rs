use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn ProjectsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();

    let (projects, set_projects) = signal::<Vec<ProjectInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (new_project_name, set_new_project_name) = signal(String::new());
    let (creating, set_creating) = signal(false);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/import", Default::default());
        }
    });

    // Load projects on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            let ws = workspace();
            if auth_clone.is_authenticated() && !ws.is_empty() {
                spawn_local(async move {
                    fetch_projects(auth_clone, &ws, set_projects, set_loading, set_error).await;
                });
            }
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = set_projects;
        set_loading.set(false);
    }

    // Create project handler
    let on_create = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let name = new_project_name.get();
        let ws = workspace();
        if name.is_empty() || ws.is_empty() {
            return;
        }

        set_creating.set(true);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let name_clone = name.clone();
            let ws_clone = ws.clone();
            spawn_local(async move {
                match create_project_api(auth_clone, &ws_clone, &name_clone).await {
                    Ok(project) => {
                        set_projects.update(|ps| {
                            ps.push(ProjectInfo {
                                id: project.id,
                                name: project.name,
                                environment_count: 0,
                            });
                        });
                        set_new_project_name.set(String::new());
                        set_show_create_modal.set(false);
                    }
                    Err(e) => {
                        set_error.set(Some(format!("Failed to create project: {}", e)));
                    }
                }
                set_creating.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (name, ws);
            set_creating.set(false);
        }
    };

    view! {
        <Layout>
            <div class="space-y-6">
                // Breadcrumb
                <div class="text-sm breadcrumbs">
                    <ul>
                        <li><a href="/workspaces">"Workspaces"</a></li>
                        <li>{workspace}</li>
                    </ul>
                </div>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Projects"</h1>
                    <div class="flex gap-2">
                        <a
                            href=move || format!("/workspaces/{}/invites", workspace())
                            class="btn btn-outline"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                            </svg>
                            "Invite"
                        </a>
                        <a
                            href=move || format!("/workspaces/{}/permissions", workspace())
                            class="btn btn-outline"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                            "Permissions"
                        </a>
                        <button
                            class="btn btn-primary"
                            on:click=move |_| set_show_create_modal.set(true)
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                            </svg>
                            "Create Project"
                        </button>
                    </div>
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

                <Show when=move || !loading.get() && projects.get().is_empty()>
                    <div class="card bg-base-100 shadow">
                        <div class="card-body items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4">"No projects yet"</h2>
                            <p class="text-base-content/70">
                                "Create a project to organize your environments and secrets."
                            </p>
                            <button
                                class="btn btn-primary mt-4"
                                on:click=move |_| set_show_create_modal.set(true)
                            >
                                "Create First Project"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !projects.get().is_empty()>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <For
                            each=move || projects.get()
                            key=|p| p.id.clone()
                            children=move |proj| {
                                let ws = workspace();
                                let name = proj.name.clone();
                                let display_name = proj.name.clone();
                                let env_count = proj.environment_count;
                                view! {
                                    <a href=format!("/workspaces/{}/projects/{}", ws, name) class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                                        <div class="card-body">
                                            <h2 class="card-title">{display_name}</h2>
                                            <p class="text-base-content/70">
                                                {if env_count == 1 {
                                                    "1 environment".to_string()
                                                } else {
                                                    format!("{} environments", env_count)
                                                }}
                                            </p>
                                        </div>
                                    </a>
                                }
                            }
                        />
                    </div>
                </Show>

                // Create Project Modal
                <Show when=move || show_create_modal.get()>
                    <div class="modal modal-open">
                        <div class="modal-box">
                            <h3 class="font-bold text-lg mb-4">"Create Project"</h3>
                            <form on:submit=on_create>
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Project Name"</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="my-project"
                                        class="input input-bordered"
                                        prop:value=move || new_project_name.get()
                                        on:input=move |ev| set_new_project_name.set(event_target_value(&ev))
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
                                        disabled=move || creating.get() || new_project_name.get().is_empty()
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
struct ProjectInfo {
    id: String,
    name: String,
    environment_count: usize,
}

#[cfg(target_arch = "wasm32")]
async fn fetch_projects(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    set_projects: WriteSignal<Vec<ProjectInfo>>,
    set_loading: WriteSignal<bool>,
    set_error: WriteSignal<Option<String>>,
) {
    use zopp_proto_web::{ListProjectsRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        set_loading.set(false);
        return;
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = ListProjectsRequest {
        workspace_name: workspace.to_string(),
    };

    match client.list_projects(&credentials, request).await {
        Ok(response) => {
            let items: Vec<ProjectInfo> = response
                .projects
                .into_iter()
                .map(|p| ProjectInfo {
                    id: p.id,
                    name: p.name,
                    environment_count: p.environment_count as usize,
                })
                .collect();
            set_projects.set(items);
        }
        Err(e) => {
            set_error.set(Some(format!("Failed to load projects: {}", e)));
        }
    }
    set_loading.set(false);
}

#[cfg(target_arch = "wasm32")]
async fn create_project_api(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    name: &str,
) -> Result<zopp_proto_web::Project, String> {
    use zopp_proto_web::{CreateProjectRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = CreateProjectRequest {
        workspace_name: workspace.to_string(),
        name: name.to_string(),
    };

    client
        .create_project(&credentials, request)
        .await
        .map_err(|e| e.to_string())
}
