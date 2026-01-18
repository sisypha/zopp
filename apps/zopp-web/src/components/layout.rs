use leptos::prelude::*;

use super::{Navbar, Sidebar};

#[component]
pub fn Layout(children: Children) -> impl IntoView {
    view! {
        <div class="drawer lg:drawer-open">
            <input id="main-drawer" type="checkbox" class="drawer-toggle"/>
            <div class="drawer-content flex flex-col">
                <Navbar/>
                <main class="flex-1 p-6">
                    {children()}
                </main>
            </div>
            <Sidebar/>
        </div>
    }
}
