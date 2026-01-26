//! Marketing landing page for cloud deployment (zopp.dev).
//!
//! This page is only shown on the official cloud service, not for
//! self-hosted deployments.

use leptos::prelude::*;

#[component]
pub fn CloudLandingPage() -> impl IntoView {
    view! {
        <div class="min-h-screen bg-vault-base">
            <Nav />
            <Hero />
            <Features />
            <HowItWorks />
            <Pricing />
            <CallToAction />
            <Footer />
        </div>
    }
}

#[component]
fn Nav() -> impl IntoView {
    view! {
        <nav class="fixed top-0 left-0 right-0 z-50 bg-vault-base/80 backdrop-blur-sm border-b border-terminal-border">
            <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
                <a href="/" class="flex items-center gap-2">
                    <span class="text-2xl font-bold font-mono text-amber">{r#">"#}</span>
                    <span class="text-xl font-bold text-cipher-text">{"zopp"}</span>
                </a>

                <div class="hidden md:flex items-center gap-8">
                    <a href="#features" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Features"}</a>
                    <a href="#how-it-works" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"How It Works"}</a>
                    <a href="#pricing" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Pricing"}</a>
                    <a href="https://docs.zopp.dev" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Docs"}</a>
                </div>

                <div class="flex items-center gap-3">
                    <a href="/import" class="hidden sm:inline-flex text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Sign In"}</a>
                    <a href="/invite" class="px-4 py-2 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors">{"Get Started"}</a>
                </div>
            </div>
        </nav>
    }
}

#[component]
fn Hero() -> impl IntoView {
    view! {
        <section class="pt-32 pb-20 px-6">
            <div class="max-w-4xl mx-auto text-center">
                <div class="inline-flex items-center gap-2 px-3 py-1 mb-6 text-xs font-medium rounded-full bg-amber-muted text-amber-text border border-amber/20">
                    <span class="w-1.5 h-1.5 rounded-full bg-amber animate-pulse"></span>
                    {"Open Source & Self-Hostable"}
                </div>

                <h1 class="text-4xl md:text-6xl font-bold text-cipher-text leading-tight mb-6">
                    {"Secrets management"}<br/>
                    <span class="text-amber">{"without the trust issues"}</span>
                </h1>

                <p class="text-lg md:text-xl text-cipher-secondary max-w-2xl mx-auto mb-10">
                    {"Zero-knowledge encryption means your secrets stay secret. Not even we can read them. Team collaboration without compromise."}
                </p>

                <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
                    <a href="/invite" class="w-full sm:w-auto px-8 py-3 text-base font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors">
                        {"Start for Free"}
                    </a>
                    <a href="https://github.com/faiscadev/zopp" target="_blank" class="w-full sm:w-auto px-8 py-3 text-base font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-100 transition-colors flex items-center justify-center gap-2">
                        <GithubIcon />
                        {"View on GitHub"}
                    </a>
                </div>

                <div class="mt-12 pt-8 border-t border-terminal-border-subtle">
                    <p class="text-xs text-cipher-muted uppercase tracking-wider mb-4">{"Trusted architecture"}</p>
                    <div class="flex flex-wrap items-center justify-center gap-6 text-cipher-secondary">
                        <TrustIndicator icon="shield" text="End-to-end encrypted" />
                        <TrustIndicator icon="lock" text="Zero-knowledge proof" />
                        <TrustIndicator icon="code" text="AGPL open source" />
                    </div>
                </div>
            </div>
        </section>
    }
}

#[component]
fn TrustIndicator(icon: &'static str, text: &'static str) -> impl IntoView {
    let icon_view = match icon {
        "shield" => view! {
            <svg class="w-5 h-5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
        }.into_any(),
        "lock" => view! {
            <svg class="w-5 h-5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
        }.into_any(),
        "code" => view! {
            <svg class="w-5 h-5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
        }.into_any(),
        _ => view! { <span></span> }.into_any(),
    };

    view! {
        <div class="flex items-center gap-2">
            {icon_view}
            <span class="text-sm">{text}</span>
        </div>
    }
}

#[component]
fn Features() -> impl IntoView {
    view! {
        <section id="features" class="py-20 px-6 bg-vault-100">
            <div class="max-w-6xl mx-auto">
                <div class="text-center mb-16">
                    <h2 class="text-3xl md:text-4xl font-bold text-cipher-text mb-4">{"Built for teams who care about security"}</h2>
                    <p class="text-lg text-cipher-secondary max-w-2xl mx-auto">{"All the features you need to manage secrets across your organization, without compromising on security."}</p>
                </div>

                <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <FeatureCard
                        icon="lock"
                        title="Zero-Knowledge Encryption"
                        description="Your secrets are encrypted client-side before they ever leave your device. We mathematically cannot read them."
                    />
                    <FeatureCard
                        icon="users"
                        title="Team Workspaces"
                        description="Organize secrets by workspace and share with your team. Fine-grained permissions let you control who sees what."
                    />
                    <FeatureCard
                        icon="terminal"
                        title="CLI-First Design"
                        description="Powerful CLI that integrates with your workflow. Inject secrets into any command or export to .env files."
                    />
                    <FeatureCard
                        icon="kubernetes"
                        title="Kubernetes Native"
                        description="Sync secrets directly to Kubernetes with our operator. Works with any cluster, no sidecar needed."
                    />
                    <FeatureCard
                        icon="audit"
                        title="Full Audit Trail"
                        description="Every access is logged. Know who accessed what secret, when, and from where."
                    />
                    <FeatureCard
                        icon="code"
                        title="Self-Hostable"
                        description="Run zopp on your own infrastructure. Single binary, works with SQLite or PostgreSQL."
                    />
                </div>
            </div>
        </section>
    }
}

#[component]
fn FeatureCard(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
) -> impl IntoView {
    let icon_svg = match icon {
        "lock" => view! {
            <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
        }.into_any(),
        "users" => view! {
            <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
            </svg>
        }.into_any(),
        "terminal" => view! {
            <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
            </svg>
        }.into_any(),
        "kubernetes" => view! {
            <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
            </svg>
        }.into_any(),
        "audit" => view! {
            <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/>
            </svg>
        }.into_any(),
        "code" => view! {
            <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
        }.into_any(),
        _ => view! { <span></span> }.into_any(),
    };

    view! {
        <div class="p-6 bg-vault-200 border border-terminal-border rounded-md hover:border-terminal-border-strong transition-colors">
            <div class="w-12 h-12 flex items-center justify-center rounded-sm bg-amber-muted text-amber mb-4">
                {icon_svg}
            </div>
            <h3 class="text-lg font-semibold text-cipher-text mb-2">{title}</h3>
            <p class="text-sm text-cipher-secondary leading-relaxed">{description}</p>
        </div>
    }
}

#[component]
fn HowItWorks() -> impl IntoView {
    view! {
        <section id="how-it-works" class="py-20 px-6">
            <div class="max-w-6xl mx-auto">
                <div class="text-center mb-16">
                    <h2 class="text-3xl md:text-4xl font-bold text-cipher-text mb-4">{"Get started in minutes"}</h2>
                    <p class="text-lg text-cipher-secondary max-w-2xl mx-auto">{"No complex setup. No vendor lock-in. Just secure secrets management."}</p>
                </div>

                <div class="grid md:grid-cols-3 gap-8">
                    <Step number="1" title="Create a workspace" description="Sign up and create your first workspace. Invite your team members with secure invite links." />
                    <Step number="2" title="Add your secrets" description="Use the CLI or web UI to add secrets. They're encrypted before leaving your device." />
                    <Step number="3" title="Use everywhere" description="Inject secrets into your apps, sync to Kubernetes, or export to .env files." />
                </div>

                <div class="mt-16 max-w-3xl mx-auto">
                    <div class="bg-vault-inset border border-terminal-border rounded-md overflow-hidden">
                        <div class="flex items-center gap-2 px-4 py-2 bg-vault-100 border-b border-terminal-border">
                            <div class="w-3 h-3 rounded-full bg-error/50"></div>
                            <div class="w-3 h-3 rounded-full bg-warning/50"></div>
                            <div class="w-3 h-3 rounded-full bg-success/50"></div>
                            <span class="ml-2 text-xs text-cipher-muted font-mono">{"terminal"}</span>
                        </div>
                        <pre class="p-4 text-sm font-mono text-cipher-text overflow-x-auto">
                            <code>
                                <span class="text-cipher-muted">{"# Install the CLI"}</span>{"\n"}
                                <span class="text-success">{"$"}</span>{" brew install faiscadev/tap/zopp\n\n"}
                                <span class="text-cipher-muted">{"# Join your workspace"}</span>{"\n"}
                                <span class="text-success">{"$"}</span>{" zopp join inv_abc123 alice@company.com\n\n"}
                                <span class="text-cipher-muted">{"# Add a secret"}</span>{"\n"}
                                <span class="text-success">{"$"}</span>{" zopp secret set DATABASE_URL postgres://...\n\n"}
                                <span class="text-cipher-muted">{"# Run with secrets injected"}</span>{"\n"}
                                <span class="text-success">{"$"}</span>{" zopp run -- npm start"}
                            </code>
                        </pre>
                    </div>
                </div>
            </div>
        </section>
    }
}

#[component]
fn Step(number: &'static str, title: &'static str, description: &'static str) -> impl IntoView {
    view! {
        <div class="text-center">
            <div class="w-12 h-12 flex items-center justify-center rounded-full bg-amber text-white text-xl font-bold mx-auto mb-4">
                {number}
            </div>
            <h3 class="text-lg font-semibold text-cipher-text mb-2">{title}</h3>
            <p class="text-sm text-cipher-secondary">{description}</p>
        </div>
    }
}

#[component]
fn Pricing() -> impl IntoView {
    view! {
        <section id="pricing" class="py-20 px-6 bg-vault-100">
            <div class="max-w-5xl mx-auto">
                <div class="text-center mb-16">
                    <h2 class="text-3xl md:text-4xl font-bold text-cipher-text mb-4">{"Simple, transparent pricing"}</h2>
                    <p class="text-lg text-cipher-secondary max-w-2xl mx-auto">{"Start free, scale as you grow. No surprises."}</p>
                </div>

                <div class="grid md:grid-cols-3 gap-6">
                    <PricingCard
                        name="Free"
                        price="$0"
                        period="forever"
                        description="For individuals and small projects"
                        features=vec!["Up to 3 users", "1 workspace", "100 secrets", "CLI & Web access", "Community support"]
                        cta_text="Get Started"
                        cta_href="/invite"
                        highlighted=false
                    />
                    <PricingCard
                        name="Pro"
                        price="$29"
                        period="/user/month"
                        description="For growing teams"
                        features=vec!["Unlimited users", "Unlimited workspaces", "Unlimited secrets", "RBAC permissions", "Audit logs", "Priority support"]
                        cta_text="Start Free Trial"
                        cta_href="/invite"
                        highlighted=true
                    />
                    <PricingCard
                        name="Self-Hosted"
                        price="Free"
                        period="AGPL license"
                        description="Run on your own infrastructure"
                        features=vec!["All features included", "Your infrastructure", "No usage limits", "Community support", "Source code access"]
                        cta_text="View on GitHub"
                        cta_href="https://github.com/faiscadev/zopp"
                        highlighted=false
                    />
                </div>
            </div>
        </section>
    }
}

#[component]
fn PricingCard(
    name: &'static str,
    price: &'static str,
    period: &'static str,
    description: &'static str,
    features: Vec<&'static str>,
    cta_text: &'static str,
    cta_href: &'static str,
    highlighted: bool,
) -> impl IntoView {
    let card_class = if highlighted {
        "p-6 bg-vault-200 border-2 border-amber rounded-md relative"
    } else {
        "p-6 bg-vault-200 border border-terminal-border rounded-md"
    };

    let button_class = if highlighted {
        "w-full px-4 py-2.5 text-sm font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors"
    } else {
        "w-full px-4 py-2.5 text-sm font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-100 transition-colors"
    };

    view! {
        <div class=card_class>
            {highlighted.then(|| view! {
                <div class="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 text-xs font-medium bg-amber text-white rounded-full">
                    {"Most Popular"}
                </div>
            })}

            <div class="text-center mb-6">
                <h3 class="text-lg font-semibold text-cipher-text mb-2">{name}</h3>
                <div class="flex items-baseline justify-center gap-1">
                    <span class="text-4xl font-bold text-cipher-text">{price}</span>
                    <span class="text-sm text-cipher-muted">{period}</span>
                </div>
                <p class="text-sm text-cipher-secondary mt-2">{description}</p>
            </div>

            <ul class="space-y-3 mb-6">
                {features.into_iter().map(|feature| {
                    view! {
                        <li class="flex items-center gap-2 text-sm text-cipher-secondary">
                            <CheckIcon />
                            {feature}
                        </li>
                    }
                }).collect_view()}
            </ul>

            <a href=cta_href class=button_class>
                {cta_text}
            </a>
        </div>
    }
}

#[component]
fn CallToAction() -> impl IntoView {
    view! {
        <section class="py-20 px-6">
            <div class="max-w-3xl mx-auto text-center">
                <h2 class="text-3xl md:text-4xl font-bold text-cipher-text mb-4">{"Ready to secure your secrets?"}</h2>
                <p class="text-lg text-cipher-secondary mb-8">{"Join thousands of teams who trust zopp with their most sensitive data."}</p>
                <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
                    <a href="/invite" class="w-full sm:w-auto px-8 py-3 text-base font-medium rounded-sm bg-amber text-white hover:bg-amber-hover transition-colors">
                        {"Start for Free"}
                    </a>
                    <a href="https://docs.zopp.dev" target="_blank" class="w-full sm:w-auto px-8 py-3 text-base font-medium rounded-sm bg-transparent text-cipher-text border border-terminal-border hover:border-terminal-border-strong hover:bg-vault-100 transition-colors">
                        {"View Documentation"}
                    </a>
                </div>
            </div>
        </section>
    }
}

#[component]
fn Footer() -> impl IntoView {
    view! {
        <footer class="py-12 px-6 border-t border-terminal-border">
            <div class="max-w-6xl mx-auto">
                <div class="grid md:grid-cols-4 gap-8 mb-8">
                    <div class="md:col-span-1">
                        <a href="/" class="flex items-center gap-2 mb-4">
                            <span class="text-2xl font-bold font-mono text-amber">{r#">"#}</span>
                            <span class="text-xl font-bold text-cipher-text">{"zopp"}</span>
                        </a>
                        <p class="text-sm text-cipher-secondary">{"Zero-knowledge secrets management for modern teams."}</p>
                    </div>

                    <div>
                        <h4 class="text-sm font-semibold text-cipher-text mb-4">{"Product"}</h4>
                        <ul class="space-y-2">
                            <li><a href="#features" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Features"}</a></li>
                            <li><a href="#pricing" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Pricing"}</a></li>
                            <li><a href="https://docs.zopp.dev" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Documentation"}</a></li>
                            <li><a href="https://github.com/faiscadev/zopp/releases" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Changelog"}</a></li>
                        </ul>
                    </div>

                    <div>
                        <h4 class="text-sm font-semibold text-cipher-text mb-4">{"Resources"}</h4>
                        <ul class="space-y-2">
                            <li><a href="https://github.com/faiscadev/zopp" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"GitHub"}</a></li>
                            <li><a href="https://github.com/faiscadev/zopp/issues" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Issue Tracker"}</a></li>
                            <li><a href="https://github.com/faiscadev/zopp/discussions" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Community"}</a></li>
                        </ul>
                    </div>

                    <div>
                        <h4 class="text-sm font-semibold text-cipher-text mb-4">{"Company"}</h4>
                        <ul class="space-y-2">
                            <li><a href="https://faisca.dev" target="_blank" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"About"}</a></li>
                            <li><a href="mailto:hello@faisca.dev" class="text-sm text-cipher-secondary hover:text-cipher-text transition-colors">{"Contact"}</a></li>
                        </ul>
                    </div>
                </div>

                <div class="pt-8 border-t border-terminal-border-subtle flex flex-col sm:flex-row items-center justify-between gap-4">
                    <p class="text-sm text-cipher-muted">{"© 2025 Faisca. AGPL-3.0 License."}</p>
                    <a href="https://github.com/faiscadev/zopp" target="_blank" class="text-cipher-muted hover:text-cipher-text transition-colors">
                        <GithubIcon />
                    </a>
                </div>
            </div>
        </footer>
    }
}

#[component]
fn GithubIcon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
        </svg>
    }
}

#[component]
fn CheckIcon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4 text-success flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
        </svg>
    }
}
