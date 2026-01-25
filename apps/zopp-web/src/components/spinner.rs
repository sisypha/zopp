use leptos::prelude::*;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum SpinnerSize {
    Sm,
    #[default]
    Md,
    Lg,
}

#[component]
pub fn Spinner(
    #[prop(optional)] size: SpinnerSize,
    #[prop(optional)] class: &'static str,
) -> impl IntoView {
    let base =
        "inline-block border-2 rounded-full animate-spin border-terminal-border border-t-amber";

    let size_class = match size {
        SpinnerSize::Sm => "w-4 h-4",
        SpinnerSize::Md => "w-5 h-5",
        SpinnerSize::Lg => "w-8 h-8",
    };

    view! {
        <span class=format!("{} {} {}", base, size_class, class)></span>
    }
}
