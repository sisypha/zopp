use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::state::auth::use_auth;

#[component]
pub fn LandingPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    // Redirect if already authenticated
    Effect::new(move || {
        if auth.is_authenticated() {
            navigate("/workspaces", Default::default());
        }
    });

    view! {
        <div class="min-h-screen flex items-center justify-center bg-base-200">
            <div class="card w-96 bg-base-100 shadow-xl">
                <div class="card-body text-center">
                    <div class="flex justify-center mb-4">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                        </svg>
                    </div>
                    <h1 class="text-3xl font-bold">"Zopp"</h1>
                    <p class="text-base-content/70 mt-2">
                        "Zero-knowledge secrets manager"
                    </p>

                    <div class="divider"></div>

                    <div class="space-y-4">
                        <a href="/invite" class="btn btn-primary w-full">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                            </svg>
                            "I have an invite token"
                        </a>

                        <a href="/import" class="btn btn-outline w-full">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                            </svg>
                            "Import existing principal"
                        </a>
                    </div>

                    <div class="mt-6 text-sm text-base-content/50">
                        <p>"All encryption happens in your browser."</p>
                        <p class="mt-1">"The server never sees your secrets."</p>
                    </div>
                </div>
            </div>
        </div>
    }
}
