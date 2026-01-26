use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="min-h-screen flex items-center justify-center bg-vault-base">
            <div class="text-center">
                <p class="text-9xl font-bold text-cipher-faint">"404"</p>
                <h1 class="text-2xl font-bold mt-4 text-cipher-text">"Page not found"</h1>
                <p class="text-cipher-secondary mt-2">
                    "The page you're looking for doesn't exist."
                </p>
                <A
                    href="/"
                    attr:class="inline-flex items-center justify-center gap-2 px-4 py-2 mt-6 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
                >
                    "Go home"
                </A>
            </div>
        </div>
    }
}
