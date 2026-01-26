use leptos::ev;
use leptos::prelude::*;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Ghost,
    Destructive,
}

#[derive(Default, Clone, Copy, PartialEq)]
pub enum ButtonSize {
    Sm,
    #[default]
    Md,
    Lg,
}

#[component]
pub fn Button(
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] size: ButtonSize,
    #[prop(optional)] disabled: Signal<bool>,
    #[prop(optional)] class: &'static str,
    #[prop(optional)] on_click: Option<Callback<ev::MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let base = "inline-flex items-center justify-center gap-2 font-medium rounded-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-amber/50 disabled:opacity-50 disabled:cursor-not-allowed";

    let variant_class = match variant {
        ButtonVariant::Primary => "bg-amber text-white hover:bg-amber-hover",
        ButtonVariant::Secondary => "bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-100",
        ButtonVariant::Ghost => "bg-transparent text-cipher-secondary hover:bg-vault-100 hover:text-cipher-text",
        ButtonVariant::Destructive => "bg-transparent text-error border border-error-muted hover:bg-error-muted",
    };

    let size_class = match size {
        ButtonSize::Sm => "px-3 py-1.5 text-xs",
        ButtonSize::Md => "px-4 py-2 text-sm",
        ButtonSize::Lg => "px-6 py-3 text-base",
    };

    view! {
        <button
            class=format!("{} {} {} {}", base, variant_class, size_class, class)
            disabled=move || disabled.get()
            on:click=move |e| {
                if let Some(handler) = on_click {
                    handler.run(e);
                }
            }
        >
            {children()}
        </button>
    }
}
