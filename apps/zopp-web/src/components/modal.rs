use leptos::portal::Portal;
use leptos::prelude::*;

#[component]
pub fn Modal(
    open: Signal<bool>,
    on_close: Callback<()>,
    #[prop(optional)] max_width: &'static str,
    children: ChildrenFn,
) -> impl IntoView {
    let max_w = if max_width.is_empty() { "max-w-lg" } else { max_width };
    let children = StoredValue::new(children);

    view! {
        <Show when=move || open.get()>
            <Portal mount=document().body().unwrap()>
                <div
                    class="fixed top-0 left-0 right-0 bottom-0 z-[9999] flex items-center justify-center p-4 bg-black/60"
                    on:click=move |_| on_close.run(())
                >
                    <div
                        class=format!("relative w-full rounded-lg bg-vault-100 border border-terminal-border p-6 {}", max_w)
                        on:click=move |e| e.stop_propagation()
                    >
                        {children.with_value(|c| c())}
                    </div>
                </div>
            </Portal>
        </Show>
    }
}

#[component]
pub fn ModalTitle(
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <h3 class=format!("flex items-center gap-3 text-lg font-semibold text-cipher-text mb-4 {}", class)>
            {children()}
        </h3>
    }
}

#[component]
pub fn ModalBody(
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("mb-6 {}", class)>
            {children()}
        </div>
    }
}

#[component]
pub fn ModalActions(
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("flex items-center justify-end gap-3 {}", class)>
            {children()}
        </div>
    }
}
