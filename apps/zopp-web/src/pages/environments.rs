use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn EnvironmentsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();
    let project = move || params.read().get("project").unwrap_or_default();

    let (environments, _set_environments) = signal::<Vec<EnvironmentInfo>>(vec![]);
    let (loading, set_loading) = signal(true);

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate("/login", Default::default());
        }
    });

    // Load environments
    Effect::new(move || {
        let _ws = workspace();
        let _proj = project();
        spawn_local(async move {
            // TODO: Call gRPC ListEnvironments
            set_loading.set(false);
        });
    });

    view! {
        <Layout>
            <div class="space-y-6">
                // Breadcrumb
                <div class="text-sm breadcrumbs">
                    <ul>
                        <li><a href="/workspaces">"Workspaces"</a></li>
                        <li><a href=move || format!("/workspaces/{}", workspace())>{workspace}</a></li>
                        <li>{project}</li>
                    </ul>
                </div>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Environments"</h1>
                    <button class="btn btn-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                        </svg>
                        "Create Environment"
                    </button>
                </div>

                <Show when=move || loading.get()>
                    <div class="flex justify-center py-12">
                        <span class="loading loading-spinner loading-lg"></span>
                    </div>
                </Show>

                <Show when=move || !loading.get() && environments.get().is_empty()>
                    <div class="card bg-base-100 shadow">
                        <div class="card-body items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4">"No environments yet"</h2>
                            <p class="text-base-content/70">
                                "Create an environment to store your secrets."
                            </p>
                            <button class="btn btn-primary mt-4">
                                "Create First Environment"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !environments.get().is_empty()>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {move || {
                            let ws = workspace();
                            let proj = project();
                            environments.get().iter().map(|env| {
                                let name = env.name.clone();
                                let display_name = env.name.clone();
                                let secret_count = env.secret_count;
                                let ws_clone = ws.clone();
                                let proj_clone = proj.clone();
                                view! {
                                    <a href=format!("/workspaces/{}/projects/{}/environments/{}", ws_clone, proj_clone, name) class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                                        <div class="card-body">
                                            <h2 class="card-title">{display_name}</h2>
                                            <p class="text-base-content/70">
                                                {format!("{} secrets", secret_count)}
                                            </p>
                                        </div>
                                    </a>
                                }
                            }).collect::<Vec<_>>()
                        }}
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct EnvironmentInfo {
    name: String,
    secret_count: usize,
}
