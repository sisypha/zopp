use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn PermissionsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_redirect = navigate.clone();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();

    let (permissions, set_permissions) = signal::<Vec<PermissionInfo>>(vec![]);
    let (groups, set_groups) = signal::<Vec<GroupInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);
    let (active_tab, set_active_tab) = signal("permissions".to_string());

    // Modal state for creating groups
    let (show_create_group_modal, set_show_create_group_modal) = signal(false);
    let (new_group_name, set_new_group_name) = signal(String::new());
    let (creating_group, set_creating_group) = signal(false);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate_for_redirect("/login", Default::default());
        }
    });

    // Load permissions and groups on mount
    #[cfg(target_arch = "wasm32")]
    {
        let auth_clone = auth;
        Effect::new(move || {
            let ws = workspace();
            if auth_clone.is_authenticated() && !ws.is_empty() {
                spawn_local(async move {
                    fetch_permissions_and_groups(
                        auth_clone,
                        &ws,
                        set_permissions,
                        set_groups,
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
        let _ = (set_permissions, set_groups);
        set_loading.set(false);
    }

    let on_create_group = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let name = new_group_name.get();
        let ws = workspace();
        if name.is_empty() || ws.is_empty() {
            return;
        }

        set_creating_group.set(true);

        #[cfg(target_arch = "wasm32")]
        {
            let auth_clone = auth;
            let name_clone = name.clone();
            let ws_clone = ws.clone();
            spawn_local(async move {
                match create_group_api(auth_clone, &ws_clone, &name_clone).await {
                    Ok(group) => {
                        set_groups.update(|gs| {
                            gs.push(GroupInfo {
                                id: group.id,
                                name: group.name,
                                member_count: 0,
                            });
                        });
                        set_new_group_name.set(String::new());
                        set_show_create_group_modal.set(false);
                    }
                    Err(e) => {
                        set_error.set(Some(format!("Failed to create group: {}", e)));
                    }
                }
                set_creating_group.set(false);
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (name, ws);
            set_creating_group.set(false);
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
                        <li>"Permissions"</li>
                    </ul>
                </div>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Permissions & Groups"</h1>
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

                // Tabs
                <div class="tabs tabs-boxed">
                    <a
                        class=move || if active_tab.get() == "permissions" { "tab tab-active" } else { "tab" }
                        on:click=move |_| set_active_tab.set("permissions".to_string())
                    >
                        "Permissions"
                    </a>
                    <a
                        class=move || if active_tab.get() == "groups" { "tab tab-active" } else { "tab" }
                        on:click=move |_| set_active_tab.set("groups".to_string())
                    >
                        "Groups"
                    </a>
                </div>

                <Show when=move || loading.get()>
                    <div class="flex justify-center py-12">
                        <span class="loading loading-spinner loading-lg"></span>
                    </div>
                </Show>

                // Permissions Tab
                <Show when=move || !loading.get() && active_tab.get() == "permissions">
                    <Show
                        when=move || !permissions.get().is_empty()
                        fallback=move || view! {
                            <div class="card bg-base-100 shadow">
                                <div class="card-body items-center text-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                    </svg>
                                    <h2 class="text-xl font-bold mt-4">"No permissions configured"</h2>
                                    <p class="text-base-content/70">
                                        "Permissions are automatically assigned when users join the workspace."
                                    </p>
                                </div>
                            </div>
                        }
                    >
                        <div class="overflow-x-auto">
                            <table class="table bg-base-100">
                                <thead>
                                    <tr>
                                        <th>"Principal"</th>
                                        <th>"Name"</th>
                                        <th>"Role"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For
                                        each=move || permissions.get()
                                        key=|p| p.principal_id.clone()
                                        children=move |perm| {
                                            view! {
                                                <tr>
                                                    <td class="font-mono text-sm">{perm.principal_id.clone()}</td>
                                                    <td>{perm.principal_name.clone()}</td>
                                                    <td>
                                                        <span class=move || {
                                                            let badge_class = if perm.role.contains("Admin") {
                                                                "badge-error"
                                                            } else if perm.role.contains("Write") || perm.role.contains("Member") {
                                                                "badge-warning"
                                                            } else {
                                                                "badge-info"
                                                            };
                                                            format!("badge {}", badge_class)
                                                        }>
                                                            {perm.role.clone()}
                                                        </span>
                                                    </td>
                                                </tr>
                                            }
                                        }
                                    />
                                </tbody>
                            </table>
                        </div>
                    </Show>
                </Show>

                // Groups Tab
                <Show when=move || !loading.get() && active_tab.get() == "groups">
                    <div class="flex justify-end mb-4">
                        <button
                            class="btn btn-primary"
                            on:click=move |_| set_show_create_group_modal.set(true)
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                            </svg>
                            "Create Group"
                        </button>
                    </div>

                    <Show
                        when=move || !groups.get().is_empty()
                        fallback=move || view! {
                            <div class="card bg-base-100 shadow">
                                <div class="card-body items-center text-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
                                    </svg>
                                    <h2 class="text-xl font-bold mt-4">"No groups yet"</h2>
                                    <p class="text-base-content/70">
                                        "Create groups to organize team members and assign permissions."
                                    </p>
                                    <button
                                        class="btn btn-primary mt-4"
                                        on:click=move |_| set_show_create_group_modal.set(true)
                                    >
                                        "Create First Group"
                                    </button>
                                </div>
                            </div>
                        }
                    >
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <For
                                each=move || groups.get()
                                key=|g| g.id.clone()
                                children=move |group| {
                                    let name = group.name.clone();
                                    let member_count = group.member_count;
                                    view! {
                                        <div class="card bg-base-100 shadow">
                                            <div class="card-body">
                                                <h2 class="card-title">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
                                                    </svg>
                                                    {name}
                                                </h2>
                                                <p class="text-base-content/70">
                                                    {format!("{} members", member_count)}
                                                </p>
                                            </div>
                                        </div>
                                    }
                                }
                            />
                        </div>
                    </Show>
                </Show>

                // Create Group Modal
                <Show when=move || show_create_group_modal.get()>
                    <div class="modal modal-open">
                        <div class="modal-box">
                            <h3 class="font-bold text-lg mb-4">"Create Group"</h3>
                            <form on:submit=on_create_group>
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Group Name"</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="developers"
                                        class="input input-bordered"
                                        prop:value=move || new_group_name.get()
                                        on:input=move |ev| set_new_group_name.set(event_target_value(&ev))
                                    />
                                </div>
                                <div class="modal-action">
                                    <button
                                        type="button"
                                        class="btn"
                                        on:click=move |_| set_show_create_group_modal.set(false)
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        type="submit"
                                        class="btn btn-primary"
                                        disabled=move || creating_group.get() || new_group_name.get().is_empty()
                                    >
                                        <Show when=move || creating_group.get()>
                                            <span class="loading loading-spinner loading-sm"></span>
                                        </Show>
                                        "Create"
                                    </button>
                                </div>
                            </form>
                        </div>
                        <div class="modal-backdrop" on:click=move |_| set_show_create_group_modal.set(false)></div>
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct PermissionInfo {
    principal_id: String,
    principal_name: String,
    role: String,
}

#[derive(Clone)]
struct GroupInfo {
    id: String,
    name: String,
    member_count: usize,
}

#[cfg(target_arch = "wasm32")]
async fn fetch_permissions_and_groups(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    set_permissions: WriteSignal<Vec<PermissionInfo>>,
    set_groups: WriteSignal<Vec<GroupInfo>>,
    set_loading: WriteSignal<bool>,
    set_error: WriteSignal<Option<String>>,
) {
    use zopp_proto_web::{
        ListGroupsRequest, ListWorkspacePermissionsRequest, PrincipalCredentials, ZoppWebClient,
    };

    let Some(creds) = auth.credentials() else {
        set_loading.set(false);
        return;
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id.clone(),
        ed25519_private_key: creds.ed25519_private_key.clone(),
    };

    // Fetch permissions
    let perm_request = ListWorkspacePermissionsRequest {
        workspace_name: workspace.to_string(),
    };

    let mut had_perm_error = false;
    match client
        .list_workspace_permissions(&credentials, perm_request)
        .await
    {
        Ok(response) => {
            let items: Vec<PermissionInfo> = response
                .permissions
                .into_iter()
                .map(|p| PermissionInfo {
                    principal_id: p.principal_id,
                    principal_name: p.principal_name,
                    role: format!("{:?}", p.role),
                })
                .collect();
            set_permissions.set(items);
        }
        Err(e) => {
            set_error.set(Some(format!("Failed to load permissions: {}", e)));
            had_perm_error = true;
        }
    }

    // Fetch groups
    let groups_request = ListGroupsRequest {
        workspace_name: workspace.to_string(),
    };

    match client.list_groups(&credentials, groups_request).await {
        Ok(response) => {
            let items: Vec<GroupInfo> = response
                .groups
                .into_iter()
                .map(|g| GroupInfo {
                    id: g.id,
                    name: g.name,
                    member_count: 0, // TODO: fetch member count
                })
                .collect();
            set_groups.set(items);
        }
        Err(e) => {
            // Don't overwrite permission error
            if !had_perm_error {
                set_error.set(Some(format!("Failed to load groups: {}", e)));
            }
        }
    }

    set_loading.set(false);
}

#[cfg(target_arch = "wasm32")]
async fn create_group_api(
    auth: crate::state::auth::AuthContext,
    workspace: &str,
    name: &str,
) -> Result<zopp_proto_web::Group, String> {
    use zopp_proto_web::{CreateGroupRequest, PrincipalCredentials, ZoppWebClient};

    let Some(creds) = auth.credentials() else {
        return Err("Not authenticated".to_string());
    };

    let client = ZoppWebClient::new(&auth.server_url());
    let credentials = PrincipalCredentials {
        principal_id: creds.principal_id,
        ed25519_private_key: creds.ed25519_private_key,
    };

    let request = CreateGroupRequest {
        workspace_name: workspace.to_string(),
        name: name.to_string(),
        description: String::new(),
    };

    client
        .create_group(&credentials, request)
        .await
        .map_err(|e| e.to_string())
}
