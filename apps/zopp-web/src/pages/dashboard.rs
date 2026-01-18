use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_authenticated() {
            navigate("/login", Default::default());
        }
    });

    view! {
        <Layout>
            <div class="space-y-6">
                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Dashboard"</h1>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    // Stats cards
                    <div class="stat bg-base-100 shadow rounded-lg">
                        <div class="stat-figure text-primary">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                            </svg>
                        </div>
                        <div class="stat-title">"Workspaces"</div>
                        <div class="stat-value text-primary">"0"</div>
                        <div class="stat-desc">"Accessible workspaces"</div>
                    </div>

                    <div class="stat bg-base-100 shadow rounded-lg">
                        <div class="stat-figure text-secondary">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                        </div>
                        <div class="stat-title">"Secrets"</div>
                        <div class="stat-value text-secondary">"0"</div>
                        <div class="stat-desc">"Total encrypted secrets"</div>
                    </div>

                    <div class="stat bg-base-100 shadow rounded-lg">
                        <div class="stat-figure text-accent">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                            </svg>
                        </div>
                        <div class="stat-title">"Security"</div>
                        <div class="stat-value text-accent">"Zero"</div>
                        <div class="stat-desc">"Knowledge encryption"</div>
                    </div>
                </div>

                // Quick actions
                <div class="card bg-base-100 shadow">
                    <div class="card-body">
                        <h2 class="card-title">"Quick Actions"</h2>
                        <div class="flex flex-wrap gap-4">
                            <a href="/workspaces" class="btn btn-primary">
                                "View Workspaces"
                            </a>
                        </div>
                    </div>
                </div>

                // Info card
                <div class="card bg-base-100 shadow">
                    <div class="card-body">
                        <h2 class="card-title">"About Zopp"</h2>
                        <p class="text-base-content/70">
                            "Zopp is a zero-knowledge secrets manager. All encryption happens in your browser - the server never sees your plaintext secrets."
                        </p>
                        <div class="mt-4">
                            <Show when=move || auth.principal_name().is_some()>
                                <div class="badge badge-info gap-2">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                                    </svg>
                                    {move || format!("Logged in as: {}", auth.principal_name().unwrap_or_default())}
                                </div>
                            </Show>
                        </div>
                    </div>
                </div>
            </div>
        </Layout>
    }
}
