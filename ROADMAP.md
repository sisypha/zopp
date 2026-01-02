# Roadmap

This document outlines the path to production readiness and beyond for zopp.

## Tier 0 - Deploy Blockers

Cannot deploy to production without these:

- [x] **TLS/gRPC encryption** - Add mTLS support for server-client communication
- [ ] **Docker images** - Create Dockerfiles for server and operator
- [ ] **Helm chart** - Package server + operator for easy K8s deployment
- [ ] **Health/readiness probes** - Add HTTP endpoints for K8s liveness/readiness
- [ ] **Graceful shutdown** - Handle SIGTERM for zero-downtime rolling updates

## Tier 1 - Security Essentials

Core security features for production use:

- [ ] **Structured logging (JSON)** - Replace println! with structured logs for aggregation
- [ ] **Metrics (Prometheus)** - Expose RPC latency, error rates, connection counts
- [ ] **Audit logging** - Track who accessed which secrets when
- [ ] **Fine-grained RBAC** - Read-only vs read-write principals
- [ ] **Secret versioning/history** - Ability to rollback secret changes

## Tier 2 - Operational Must-Haves

Required for running in production:

- [ ] **Backup/restore documentation** - Document RDS backup strategy and restore procedures
- [ ] **Production deployment guide** - Step-by-step guide for K8s + RDS deployment
- [ ] **Resource limits/sizing** - Document CPU/memory requirements for server and operator
- [ ] **Secret expiration/rotation** - TTL and auto-rotation support
- [ ] **Config management pattern** - Use K8s Secrets for DATABASE_URL and sensitive config

## Tier 3 - Enterprise Features

Features needed for enterprise adoption:

- [ ] **API tokens** - Simpler authentication for scripts and CI/CD (vs Ed25519 keypairs)
- [ ] **Terraform provider** - Manage zopp resources via Infrastructure-as-Code
- [ ] **Approval workflows** - Multi-person approval for production secret changes
- [ ] **Distributed tracing** - OpenTelemetry integration for debugging
- [ ] **Bulk operations** - Copy all secrets between environments

## Tier 4 - Nice-to-Haves

Quality-of-life improvements:

- [ ] **Import from other tools** - Migration scripts for 1Password, AWS Secrets Manager, etc.
- [ ] **Secret diff** - Compare secrets across environments
- [ ] **Webhooks** - Notify external systems on secret changes
- [ ] **Usage analytics** - Find orphaned or unused secrets
- [ ] **Shell completion** - Bash/zsh autocomplete for CLI

## Tier 5 - Future/Optional

Advanced features for specific use cases:

- [ ] **Web UI** - Optional web interface (CLI-first is core)
- [ ] **GitOps support** - Declarative secret definitions in Git
- [ ] **Multi-region deployment** - Active-active across regions
- [ ] **Compliance reports** - SOC2/ISO27001 audit exports

## Contributing

See [DEVELOPMENT.md](./DEVELOPMENT.md) for how to contribute to these roadmap items.
