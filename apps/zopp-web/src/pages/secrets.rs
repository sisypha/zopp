use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params_map};

use crate::components::Layout;
use crate::state::auth::use_auth;

#[component]
pub fn SecretsPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let params = use_params_map();

    let workspace = move || params.read().get("workspace").unwrap_or_default();
    let project = move || params.read().get("project").unwrap_or_default();
    let environment = move || params.read().get("environment").unwrap_or_default();

    let (secrets, _set_secrets) = signal::<Vec<SecretInfo>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (show_add_modal, set_show_add_modal) = signal(false);

    // New secret form state
    let (new_key, set_new_key) = signal(String::new());
    let (new_value, set_new_value) = signal(String::new());

    // Redirect if not authenticated
    Effect::new(move || {
        if !auth.is_loading() && !auth.is_authenticated() {
            navigate("/login", Default::default());
        }
    });

    // Load secrets
    Effect::new(move || {
        let _ws = workspace();
        let _proj = project();
        let _env = environment();
        spawn_local(async move {
            // TODO: Call gRPC ListSecrets + decrypt
            set_loading.set(false);
        });
    });

    let on_add_secret = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let _key = new_key.get();
        let _value = new_value.get();

        // TODO: Encrypt with DEK and call UpsertSecret
        spawn_local(async move {
            // Implement secret creation
            set_show_add_modal.set(false);
            set_new_key.set(String::new());
            set_new_value.set(String::new());
        });
    };

    view! {
        <Layout>
            <div class="space-y-6">
                // Breadcrumb
                <div class="text-sm breadcrumbs">
                    <ul>
                        <li><a href="/workspaces">"Workspaces"</a></li>
                        <li><a href=move || format!("/workspaces/{}", workspace())>{workspace}</a></li>
                        <li><a href=move || format!("/workspaces/{}/projects/{}", workspace(), project())>{project}</a></li>
                        <li>{environment}</li>
                    </ul>
                </div>

                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">"Secrets"</h1>
                    <button class="btn btn-primary" on:click=move |_| set_show_add_modal.set(true)>
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                        </svg>
                        "Add Secret"
                    </button>
                </div>

                <Show when=move || loading.get()>
                    <div class="flex justify-center py-12">
                        <span class="loading loading-spinner loading-lg"></span>
                    </div>
                </Show>

                <Show when=move || !loading.get() && secrets.get().is_empty()>
                    <div class="card bg-base-100 shadow">
                        <div class="card-body items-center text-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-base-content/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                            <h2 class="text-xl font-bold mt-4">"No secrets yet"</h2>
                            <p class="text-base-content/70">
                                "Add your first secret to this environment."
                            </p>
                            <button class="btn btn-primary mt-4" on:click=move |_| set_show_add_modal.set(true)>
                                "Add First Secret"
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || !loading.get() && !secrets.get().is_empty()>
                    <div class="overflow-x-auto">
                        <table class="table bg-base-100">
                            <thead>
                                <tr>
                                    <th>"Key"</th>
                                    <th>"Value"</th>
                                    <th>"Actions"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {move || secrets.get().iter().map(|secret| {
                                    let key = secret.key.clone();
                                    let value = secret.value.clone();
                                    let (show_value, set_show_value) = signal(false);
                                    view! {
                                        <tr>
                                            <td class="font-mono">{key.clone()}</td>
                                            <td>
                                                {move || {
                                                    if show_value.get() {
                                                        view! { <span class="font-mono">{value.clone()}</span> }.into_any()
                                                    } else {
                                                        view! { <span class="text-base-content/50">"********"</span> }.into_any()
                                                    }
                                                }}
                                            </td>
                                            <td>
                                                <div class="flex gap-2">
                                                    <button
                                                        class="btn btn-ghost btn-sm"
                                                        on:click=move |_| set_show_value.update(|v| *v = !*v)
                                                    >
                                                        {move || {
                                                            if show_value.get() {
                                                                view! {
                                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                                                                    </svg>
                                                                }.into_any()
                                                            } else {
                                                                view! {
                                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                                                                    </svg>
                                                                }.into_any()
                                                            }
                                                        }}
                                                    </button>
                                                    <button class="btn btn-ghost btn-sm btn-error">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                                        </svg>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    }
                                }).collect::<Vec<_>>()}
                            </tbody>
                        </table>
                    </div>
                </Show>

                // Add Secret Modal
                <Show when=move || show_add_modal.get()>
                    <div class="modal modal-open">
                        <div class="modal-box">
                            <h3 class="font-bold text-lg">"Add Secret"</h3>
                            <form on:submit=on_add_secret class="space-y-4 mt-4">
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Key"</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="DATABASE_URL"
                                        class="input input-bordered font-mono"
                                        prop:value=move || new_key.get()
                                        on:input=move |ev| set_new_key.set(event_target_value(&ev))
                                    />
                                </div>
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text">"Value"</span>
                                    </label>
                                    <textarea
                                        placeholder="Enter secret value"
                                        class="textarea textarea-bordered font-mono"
                                        rows="3"
                                        prop:value=move || new_value.get()
                                        on:input=move |ev| set_new_value.set(event_target_value(&ev))
                                    ></textarea>
                                </div>
                                <div class="modal-action">
                                    <button type="button" class="btn" on:click=move |_| set_show_add_modal.set(false)>
                                        "Cancel"
                                    </button>
                                    <button type="submit" class="btn btn-primary">
                                        "Add Secret"
                                    </button>
                                </div>
                            </form>
                        </div>
                        <div class="modal-backdrop" on:click=move |_| set_show_add_modal.set(false)></div>
                    </div>
                </Show>
            </div>
        </Layout>
    }
}

#[derive(Clone)]
struct SecretInfo {
    key: String,
    value: String,
}
