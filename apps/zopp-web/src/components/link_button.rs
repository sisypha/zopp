use leptos::prelude::*;

use crate::components::{ButtonSize, ButtonVariant};

#[component]
pub fn LinkButton(
    href: &'static str,
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] size: ButtonSize,
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    let base = "inline-flex items-center justify-center gap-2 font-medium rounded-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-amber/50";

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
        <a
            href=href
            class=format!("{} {} {} {}", base, variant_class, size_class, class)
        >
            {children()}
        </a>
    }
}
