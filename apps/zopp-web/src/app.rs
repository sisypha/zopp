use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{
    components::{Route, Router, Routes},
    path,
};

use crate::pages::{
    dashboard::DashboardPage, environments::EnvironmentsPage, invites::InvitesPage,
    landing::LandingPage, login::LoginPage, not_found::NotFoundPage, permissions::PermissionsPage,
    projects::ProjectsPage, register::RegisterPage, secrets::SecretsPage, settings::SettingsPage,
    workspaces::WorkspacesPage,
};
use crate::state::auth::AuthProvider;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/zopp-web.css"/>
        <Link rel="shortcut icon" type_="image/ico" href="/favicon.ico"/>
        <Meta name="description" content="Zopp - Zero-knowledge secrets manager"/>

        <Title text="Zopp"/>

        <AuthProvider>
            <Router>
                <main class="min-h-screen bg-base-200">
                    <Routes fallback=|| view! { <NotFoundPage/> }>
                        <Route path=path!("/") view=LandingPage/>
                        <Route path=path!("/login") view=LoginPage/>
                        <Route path=path!("/import") view=LoginPage/>
                        <Route path=path!("/register") view=RegisterPage/>
                        <Route path=path!("/invite") view=RegisterPage/>
                        <Route path=path!("/dashboard") view=DashboardPage/>
                        <Route path=path!("/settings") view=SettingsPage/>
                        <Route path=path!("/workspaces") view=WorkspacesPage/>
                        <Route path=path!("/workspaces/:workspace") view=ProjectsPage/>
                        <Route path=path!("/workspaces/:workspace/invites") view=InvitesPage/>
                        <Route path=path!("/workspaces/:workspace/permissions") view=PermissionsPage/>
                        <Route path=path!("/workspaces/:workspace/projects/:project") view=EnvironmentsPage/>
                        <Route path=path!("/workspaces/:workspace/projects/:project/environments/:environment") view=SecretsPage/>
                    </Routes>
                </main>
            </Router>
        </AuthProvider>
    }
}
