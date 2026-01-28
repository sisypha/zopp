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
            navigate_for_redirect("/import", Default::default());
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
                <nav class="breadcrumbs flex items-center gap-2 text-sm" data-testid="breadcrumb">
                    <a href=move || format!("/workspaces/{}", workspace()) class="text-cipher-secondary hover:text-cipher-text transition-colors">{workspace}</a>
                    <span class="text-cipher-muted">"/"</span>
                    <span class="text-cipher-text">"Permissions"</span>
                </nav>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold text-cipher-text">"Permissions & Groups"</h1>
                </div>

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

                // Tabs
                <div class="tabs flex gap-1 p-1 rounded-lg bg-vault-inset" data-testid="tabs">
                    <button
                        class=move || if active_tab.get() == "permissions" {
                            "px-4 py-2 text-sm font-medium rounded-md bg-vault-100 text-cipher-text transition-colors"
                        } else {
                            "px-4 py-2 text-sm font-medium rounded-md text-cipher-secondary hover:text-cipher-text transition-colors"
                        }
                        on:click=move |_| set_active_tab.set("permissions".to_string())
                    >
                        "Permissions"
                    </button>
                    <button
                        class=move || if active_tab.get() == "groups" {
                            "px-4 py-2 text-sm font-medium rounded-md bg-vault-100 text-cipher-text transition-colors"
                        } else {
                            "px-4 py-2 text-sm font-medium rounded-md text-cipher-secondary hover:text-cipher-text transition-colors"
                        }
                        on:click=move |_| set_active_tab.set("groups".to_string())
                    >
                        "Groups"
                    </button>
                </div>

                <Show when=move || loading.get()>
                    <div class="flex justify-center py-12">
                        <span class="inline-block w-8 h-8 border-4 rounded-full animate-spin border-amber/30 border-t-amber"></span>
                    </div>
                </Show>

                // Permissions Tab
                <Show when=move || !loading.get() && active_tab.get() == "permissions">
                    <Show
                        when=move || !permissions.get().is_empty()
                        fallback=move || view! {
                            <div class="bg-vault-100 border border-terminal-border rounded-md">
                                <div class="p-12 flex flex-col items-center text-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-cipher-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                    </svg>
                                    <h2 class="text-xl font-bold mt-4 text-cipher-text">"No permissions configured"</h2>
                                    <p class="text-cipher-secondary mt-2">
                                        "Permissions are automatically assigned when users join the workspace."
                                    </p>
                                </div>
                            </div>
                        }
                    >
                        <div class="overflow-x-auto bg-vault-100 border border-terminal-border rounded-md">
                            <table class="w-full text-sm">
                                <thead>
                                    <tr class="border-b border-terminal-border-subtle">
                                        <th class="text-left px-4 py-3 font-medium text-cipher-secondary">"Principal"</th>
                                        <th class="text-left px-4 py-3 font-medium text-cipher-secondary">"Name"</th>
                                        <th class="text-left px-4 py-3 font-medium text-cipher-secondary">"Role"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For
                                        each=move || permissions.get()
                                        key=|p| p.principal_id.clone()
                                        children=move |perm| {
                                            view! {
                                                <tr class="border-b border-terminal-border-subtle last:border-b-0">
                                                    <td class="px-4 py-3 font-mono text-sm text-cipher-text">{perm.principal_id.clone()}</td>
                                                    <td class="px-4 py-3 text-cipher-text">{perm.principal_name.clone()}</td>
                                                    <td class="px-4 py-3">
                                                        <span class=move || {
                                                            let base = "inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full";
                                                            if perm.role.contains("Admin") {
                                                                format!("{} bg-error-muted text-error", base)
                                                            } else if perm.role.contains("Write") || perm.role.contains("Member") {
                                                                format!("{} bg-amber-muted text-amber", base)
                                                            } else {
                                                                format!("{} bg-info-muted text-info", base)
                                                            }
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
                            class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
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
                            <div class="bg-vault-100 border border-terminal-border rounded-md">
                                <div class="p-12 flex flex-col items-center text-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-cipher-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
                                    </svg>
                                    <h2 class="text-xl font-bold mt-4 text-cipher-text">"No groups yet"</h2>
                                    <p class="text-cipher-secondary mt-2">
                                        "Create groups to organize team members and assign permissions."
                                    </p>
                                    <button
                                        class="inline-flex items-center justify-center gap-2 px-4 py-2 mt-6 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
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
                                        <div class="bg-vault-100 border border-terminal-border rounded-md p-6">
                                            <h2 class="flex items-center gap-2 text-lg font-semibold text-cipher-text">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
                                                </svg>
                                                {name}
                                            </h2>
                                            <p class="text-cipher-secondary mt-1">
                                                {format!("{} members", member_count)}
                                            </p>
                                        </div>
                                    }
                                }
                            />
                        </div>
                    </Show>
                </Show>

                // Create Group Modal
                <Show when=move || show_create_group_modal.get()>
                    <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" on:click=move |_| set_show_create_group_modal.set(false)>
                        <div class="relative w-full max-w-md rounded-lg bg-vault-100 border border-terminal-border p-6" on:click=move |ev| ev.stop_propagation()>
                            <h3 class="text-lg font-semibold text-cipher-text mb-4">"Create Group"</h3>
                            <form on:submit=on_create_group>
                                <div class="mb-6">
                                    <div class="space-y-1.5">
                                        <label class="block text-sm font-medium text-cipher-text">"Group Name"</label>
                                        <input
                                            type="text"
                                            placeholder="developers"
                                            class="w-full px-3 py-2.5 text-sm rounded-sm bg-control-bg border border-control-border text-cipher-text placeholder:text-cipher-muted focus:outline-none focus:border-amber focus:ring-2 focus:ring-amber/30 transition-colors"
                                            prop:value=move || new_group_name.get()
                                            on:input=move |ev| set_new_group_name.set(event_target_value(&ev))
                                        />
                                    </div>
                                </div>
                                <div class="flex items-center justify-end gap-3">
                                    <button
                                        type="button"
                                        class="px-4 py-2 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-200 transition-colors"
                                        on:click=move |_| set_show_create_group_modal.set(false)
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        type="submit"
                                        class="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                        disabled=move || creating_group.get() || new_group_name.get().is_empty()
                                    >
                                        <Show when=move || creating_group.get()>
                                            <span class="inline-block w-4 h-4 border-2 rounded-full animate-spin border-white/30 border-t-white"></span>
                                        </Show>
                                        "Create"
                                    </button>
                                </div>
                            </form>
                        </div>
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
