use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::state::auth::use_auth;
use crate::state::workspace::use_workspace;

#[component]
pub fn LandingPage() -> impl IntoView {
    let auth = use_auth();
    let workspace_ctx = use_workspace();
    let navigate = use_navigate();

    // Fetch workspaces when authenticated
    Effect::new(move || {
        if auth.is_authenticated() && !auth.is_loading() {
            workspace_ctx.fetch_workspaces(auth);
        }
    });

    // Redirect to current workspace when available
    Effect::new(move || {
        if auth.is_authenticated() && !workspace_ctx.is_loading() {
            if let Some(ws) = workspace_ctx.current() {
                navigate(&format!("/workspaces/{}", ws.name), Default::default());
            }
        }
    });

    view! {
        <div class="min-h-screen flex items-center justify-center bg-vault-base">
            <div class="bg-vault-100 border border-terminal-border rounded-md p-8 w-96">
                <div class="text-center">
                    <h1 class="text-3xl font-bold font-mono text-cipher-text">"zopp"</h1>
                    <p class="text-cipher-secondary mt-2">
                        "Zero-knowledge secrets manager"
                    </p>

                    <div class="my-6 border-t border-terminal-border"></div>

                    <div class="space-y-3">
                        <a
                            href="/invite"
                            class="flex items-center justify-center gap-2 w-full px-4 py-2.5 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                            </svg>
                            "I have an invite token"
                        </a>

                        <a
                            href="/import"
                            class="flex items-center justify-center gap-2 w-full px-4 py-2.5 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-200 transition-colors"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                            </svg>
                            "Import existing principal"
                        </a>
                    </div>

                    <div class="mt-6 text-sm text-cipher-muted">
                        <p>"All encryption happens in your browser."</p>
                        <p class="mt-1">"The server never sees your secrets."</p>
                    </div>
                </div>
            </div>
        </div>
    }
}
