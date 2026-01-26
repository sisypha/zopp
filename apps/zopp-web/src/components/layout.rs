use leptos::prelude::*;

use super::Sidebar;

#[component]
pub fn Layout(children: Children) -> impl IntoView {
    view! {
        <div class="flex min-h-screen">
            <input id="main-drawer" type="checkbox" class="hidden peer"/>
            <Sidebar/>
            <div class="flex-1 min-w-0 flex flex-col min-h-screen">
                // Mobile header (only visible on small screens)
                <div class="lg:hidden flex items-center gap-2 p-4 border-b border-terminal-border bg-vault-100">
                    <label for="main-drawer" class="p-2 rounded-sm text-cipher-secondary hover:bg-vault-100 hover:text-cipher-text transition-colors cursor-pointer">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="w-5 h-5 stroke-current">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
                        </svg>
                    </label>
                    <a href="/" class="text-lg font-semibold font-mono text-cipher-text">
                        "zopp"
                    </a>
                </div>
                <main class="flex-1 p-6 bg-vault-base">
                    {children()}
                </main>
            </div>
        </div>
    }
}
