---
sidebar_position: 1
title: Introduction
description: zopp is the open-source, self-hostable, CLI-first secrets manager with zero-knowledge encryption.
slug: /
---

# Introduction

**zopp** is the open-source secrets manager that keeps your team's secrets safe with zero-knowledge encryption. Self-host it, own your data, and stay in control.

<div className="row margin-bottom--lg">
  <div className="col col--6">
    <a className="card" href="/zopp/quickstart">
      <div className="card__body">
        <h3>Quickstart</h3>
        <p>Get up and running in 5 minutes</p>
      </div>
    </a>
  </div>
  <div className="col col--6">
    <a className="card" href="https://github.com/faiscadev/zopp">
      <div className="card__body">
        <h3>View on GitHub</h3>
        <p>Star, fork, or contribute</p>
      </div>
    </a>
  </div>
</div>

## Why zopp?

<div className="row">
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Zero-Knowledge</h3>
        <p>Your secrets are encrypted client-side before they ever reach the server. The server stores only encrypted blobs and can never see your plaintext data.</p>
      </div>
    </div>
  </div>
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Self-Hostable</h3>
        <p>Deploy zopp on your own infrastructure. No vendor lock-in, no third-party access to your secrets. Your data stays where you control it.</p>
      </div>
    </div>
  </div>
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>CLI-First</h3>
        <p>Designed for developers who live in the terminal. Import/export `.env` files, inject secrets into processes, and integrate with your existing workflow.</p>
      </div>
    </div>
  </div>
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Team Collaboration</h3>
        <p>Share secrets securely across your team with workspace invites. Fine-grained RBAC controls who can read, write, or admin each environment.</p>
      </div>
    </div>
  </div>
</div>

## Quick Example

```bash
# Set a secret
zopp secret set DATABASE_URL "postgresql://user:pass@localhost/db"

# Get a secret
zopp secret get DATABASE_URL

# Run a command with secrets injected
zopp run -- npm start

# Export to .env file
zopp secret export -o .env
```

## How It Works

zopp uses a hierarchical key encryption scheme:

```
User
 └── Principal (your device)
      └── Workspace (your team)
           └── KEK (wrapped per-principal via ECDH)
                └── Environment (dev, staging, prod)
                     └── DEK (wrapped with KEK)
                          └── Secrets (encrypted with DEK)
```

Every layer is encrypted. The server only stores wrapped keys and encrypted secrets—it never has access to plaintext.

## Getting Started

<div className="row">
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Quickstart</h3>
        <p>Get up and running in 5 minutes with our <a href="/zopp/quickstart">quickstart guide</a>.</p>
      </div>
    </div>
  </div>
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Installation</h3>
        <p>Multiple ways to install: <a href="/zopp/installation/cli">CLI</a>, <a href="/zopp/installation/docker">Docker</a>, or <a href="/zopp/installation/kubernetes">Kubernetes</a>.</p>
      </div>
    </div>
  </div>
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Core Concepts</h3>
        <p>Learn about <a href="/zopp/guides/core-concepts">workspaces, projects, and environments</a>.</p>
      </div>
    </div>
  </div>
  <div className="col col--6 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Self-Host</h3>
        <p>Deploy your own zopp server with our <a href="/zopp/self-hosting">self-hosting guide</a>.</p>
      </div>
    </div>
  </div>
</div>
