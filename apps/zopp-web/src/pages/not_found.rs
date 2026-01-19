use leptos::prelude::*;

#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="min-h-screen flex items-center justify-center bg-base-200">
            <div class="text-center">
                <p class="text-9xl font-bold text-base-content/20">"404"</p>
                <h1 class="text-2xl font-bold mt-4">"Page Not Found"</h1>
                <p class="text-base-content/70 mt-2">
                    "The page you're looking for doesn't exist."
                </p>
                <a href="/" class="btn btn-primary mt-6">
                    "Go Home"
                </a>
            </div>
        </div>
    }
}
