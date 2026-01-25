use leptos::prelude::*;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum CardVariant {
    #[default]
    Default,
    Danger,
}

#[component]
pub fn Card(
    #[prop(optional)] variant: CardVariant,
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    let base = "bg-vault-100 border rounded-md p-4 transition-colors";

    let variant_class = match variant {
        CardVariant::Default => "border-terminal-border hover:border-terminal-border-strong",
        CardVariant::Danger => "border-error-muted",
    };

    view! {
        <div class=format!("{} {} {}", base, variant_class, class)>
            {children()}
        </div>
    }
}

#[component]
pub fn CardTitle(
    #[prop(optional)] class: &'static str,
    #[prop(optional)] error: bool,
    children: Children,
) -> impl IntoView {
    let color = if error { "text-error" } else { "text-cipher-text" };

    view! {
        <h2 class=format!("flex items-center gap-2 text-base font-medium mb-2 {} {}", color, class)>
            {children()}
        </h2>
    }
}

#[component]
pub fn CardBody(
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("space-y-4 {}", class)>
            {children()}
        </div>
    }
}

#[component]
pub fn CardActions(
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("flex items-center justify-end gap-3 mt-4 {}", class)>
            {children()}
        </div>
    }
}
