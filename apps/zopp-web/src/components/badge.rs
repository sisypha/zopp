use leptos::prelude::*;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum BadgeVariant {
    #[default]
    Neutral,
    Amber,
    Success,
    Warning,
    Error,
    Info,
}

#[component]
pub fn Badge(
    #[prop(optional)] variant: BadgeVariant,
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    let base = "inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full uppercase tracking-wide";

    let variant_class = match variant {
        BadgeVariant::Neutral => "bg-vault-inset text-cipher-secondary",
        BadgeVariant::Amber => "bg-amber-muted text-amber-text",
        BadgeVariant::Success => "bg-success-muted text-success",
        BadgeVariant::Warning => "bg-warning-muted text-warning",
        BadgeVariant::Error => "bg-error-muted text-error",
        BadgeVariant::Info => "bg-info-muted text-info",
    };

    view! {
        <span class=format!("{} {} {}", base, variant_class, class)>
            {children()}
        </span>
    }
}
