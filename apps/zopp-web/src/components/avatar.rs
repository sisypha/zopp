use leptos::prelude::*;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum AvatarSize {
    Sm,
    #[default]
    Md,
    Lg,
}

#[component]
pub fn Avatar(
    #[prop(optional)] size: AvatarSize,
    #[prop(optional)] class: &'static str,
    children: Children,
) -> impl IntoView {
    let base = "relative inline-flex items-center justify-center rounded-full overflow-hidden bg-amber-muted text-amber-text font-medium";

    let size_class = match size {
        AvatarSize::Sm => "w-8 h-8 text-xs",
        AvatarSize::Md => "w-10 h-10 text-sm",
        AvatarSize::Lg => "w-12 h-12 text-base",
    };

    view! {
        <div class=format!("{} {} {}", base, size_class, class)>
            {children()}
        </div>
    }
}
