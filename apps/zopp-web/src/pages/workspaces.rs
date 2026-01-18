use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn WorkspacesPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    let (workspaces, _set_workspaces) = signal::<Vec<WorkspaceInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, _set_error) = signal::<Option<String>>(None);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate("/login", Default::default());
        }
    });

    // Load workspaces
    Effect::new(move || {
        spawn_local(async move {
            // TODO: Call gRPC ListWorkspaces
            set_loading.set(false);
            // For now, show empty state
        });
    });

    view! {
        <Layout>
            <div class="space-y-6">
                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Workspaces"</h1>
                    <button class="btn btn-primary">
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
                            <button class="btn btn-primary mt-4">
                                "Create First Workspace"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !workspaces.get().is_empty()>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {move || workspaces.get().iter().map(|ws| {
                            let name = ws.name.clone();
                            let display_name = ws.name.clone();
                            let project_count = ws.project_count;
                            view! {
                                <a href=format!("/workspaces/{}", name) class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                                    <div class="card-body">
                                        <h2 class="card-title">{display_name}</h2>
                                        <p class="text-base-content/70">
                                            {format!("{} projects", project_count)}
                                        </p>
                                    </div>
                                </a>
                            }
                        }).collect::<Vec<_>>()}
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct WorkspaceInfo {
    name: String,
    project_count: usize,
}
