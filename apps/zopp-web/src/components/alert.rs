use leptos::prelude::*;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum AlertVariant {
    #[default]
    Info,
    Success,
    Warning,
    Error,
}

#[component]
pub fn Alert(
    #[prop(optional)] variant: AlertVariant,
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    let base = "flex items-start gap-3 p-4 rounded-md text-sm border";

    let variant_class = match variant {
        AlertVariant::Info => "border-info-muted bg-info-muted text-info",
        AlertVariant::Success => "border-success-muted bg-success-muted text-success",
        AlertVariant::Warning => "border-warning-muted bg-warning-muted text-warning",
        AlertVariant::Error => "border-error-muted bg-error-muted text-error",
    };

    view! {
        <div class=format!("{} {} {}", base, variant_class, class)>
            {children()}
        </div>
    }
}
