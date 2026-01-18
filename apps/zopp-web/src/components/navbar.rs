use leptos::prelude::*;

use crate::state::auth::use_auth;

#[component]
pub fn Navbar() -> impl IntoView {
    let auth = use_auth();

    view! {
        <div class="navbar bg-base-100 shadow-lg">
            <div class="flex-none lg:hidden">
                <label for="main-drawer" class="btn btn-square btn-ghost">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="inline-block w-6 h-6 stroke-current">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
                    </svg>
                </label>
            </div>
            <div class="flex-1">
                <a href="/" class="btn btn-ghost text-xl">
                    <span class="font-bold">Zopp</span>
                </a>
            </div>
            <div class="flex-none gap-2">
                <Show when=move || auth.is_authenticated()>
                    <div class="dropdown dropdown-end">
                        <div tabindex="0" role="button" class="btn btn-ghost btn-circle avatar placeholder">
                            <div class="bg-neutral text-neutral-content rounded-full w-10">
                                <span class="text-xs">
                                    {move || auth.principal_name().map(|n| n.chars().next().unwrap_or('U').to_uppercase().to_string()).unwrap_or_else(|| "U".to_string())}
                                </span>
                            </div>
                        </div>
                        <ul tabindex="0" class="mt-3 z-[1] p-2 shadow menu menu-sm dropdown-content bg-base-100 rounded-box w-52">
                            <li><a href="/settings">"Settings"</a></li>
                            <li>
                                <button on:click=move |_| auth.logout()>
                                    "Logout"
                                </button>
                            </li>
                        </ul>
                    </div>
                </Show>
            </div>
        </div>
    }
}
