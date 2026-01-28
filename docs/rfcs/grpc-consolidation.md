# RFC: gRPC API Consolidation

- **Status:** Draft
- **Author:** Claude (Analysis)
- **Created:** 2025-01-28
- **Target:** Reduce 106 methods to 60 methods

## Summary

The zopp gRPC API has grown to 106 methods, with significant bloat from permission-related endpoints. This RFC proposes consolidating the API by introducing generic permission methods with resource/actor type parameters, reducing the method count by approximately 43%.

## Current State: 106 Methods

### Method Breakdown by Category

| Category | Count | Methods |
|----------|-------|---------|
| Auth & Email Verification | 5 | Join, Register, Login, VerifyEmail, ResendVerification |
| Workspaces | 4 | CreateWorkspace, ListWorkspaces, GetWorkspaceKeys, GrantPrincipalWorkspaceAccess |
| Invites | 4 | CreateInvite, GetInvite, ListInvites, RevokeInvite |
| Principals | 6 | GetPrincipal, RenamePrincipal, ListPrincipals, ListWorkspaceServicePrincipals, RemovePrincipalFromWorkspace, RevokeAllPrincipalPermissions |
| Principal Export/Import | 3 | CreatePrincipalExport, GetPrincipalExport, ConsumePrincipalExport |
| Projects | 4 | CreateProject, ListProjects, GetProject, DeleteProject |
| Environments | 4 | CreateEnvironment, ListEnvironments, GetEnvironment, DeleteEnvironment |
| Secrets | 4 | UpsertSecret, GetSecret, ListSecrets, DeleteSecret |
| Watch (streaming) | 1 | WatchSecrets |
| **Principal Permissions** | **12** | Set/Get/List/Remove × Workspace/Project/Environment |
| Groups CRUD | 5 | CreateGroup, GetGroup, ListGroups, UpdateGroup, DeleteGroup |
| Group Membership | 4 | AddGroupMember, RemoveGroupMember, ListGroupMembers, ListUserGroups |
| **Group Permissions** | **12** | SetGroup/GetGroup/ListGroup/RemoveGroup × Workspace/Project/Environment Permission |
| **User Permissions** | **12** | SetUser/GetUser/ListUser/RemoveUser × Workspace/Project/Environment Permission |
| Effective Permissions | 1 | GetEffectivePermissions |
| Audit Logs | 3 | ListAuditLogs, GetAuditLog, CountAuditLogs |
| Organizations | 5 | CreateOrganization, GetOrganization, ListUserOrganizations, UpdateOrganization, DeleteOrganization |
| Organization Members | 5 | AddOrganizationMember, GetOrganizationMember, ListOrganizationMembers, UpdateOrganizationMemberRole, RemoveOrganizationMember |
| Organization Invites | 5 | CreateOrganizationInvite, GetOrganizationInvite, ListOrganizationInvites, AcceptOrganizationInvite, DeleteOrganizationInvite |
| Organization Workspaces | 3 | LinkWorkspaceToOrganization, UnlinkWorkspaceFromOrganization, ListOrganizationWorkspaces |
| Billing | 4 | GetSubscription, ListPayments, CreateCheckoutSession, CreateBillingPortalSession |
| **TOTAL** | **106** | |

### The Permission Problem

The most significant bloat comes from permission methods:

```
3 actor types × 3 resource levels × 4 operations = 36 methods

Actor types:
  - Principal (direct principal permissions)
  - Group (group-based permissions)
  - User (user-based permissions)

Resource levels:
  - Workspace
  - Project
  - Environment

Operations:
  - Set
  - Get
  - List
  - Remove
```

These 36 methods represent **34% of the entire API** but could be reduced to **4 generic methods**.

---

## Proposed Consolidation

### 1. Generic Permission Methods (36 → 4 methods)

**Before:** 36 separate methods
```protobuf
rpc SetWorkspacePermission(...)
rpc GetWorkspacePermission(...)
rpc ListWorkspacePermissions(...)
rpc RemoveWorkspacePermission(...)
rpc SetProjectPermission(...)
// ... 32 more ...
```

**After:** 4 generic methods with enums
```protobuf
enum ResourceType {
  RESOURCE_WORKSPACE = 0;
  RESOURCE_PROJECT = 1;
  RESOURCE_ENVIRONMENT = 2;
}

enum ActorType {
  ACTOR_PRINCIPAL = 0;  // Service principals
  ACTOR_GROUP = 1;      // Groups
  ACTOR_USER = 2;       // Direct user permissions
}

message ResourceRef {
  ResourceType type = 1;
  string workspace_name = 2;
  optional string project_name = 3;      // Required for PROJECT, ENVIRONMENT
  optional string environment_name = 4;  // Required for ENVIRONMENT
}

message ActorRef {
  ActorType type = 1;
  oneof actor {
    string principal_id = 2;  // For ACTOR_PRINCIPAL
    string group_name = 3;    // For ACTOR_GROUP
    string user_email = 4;    // For ACTOR_USER
  }
}

// Generic permission methods
rpc SetPermission(SetPermissionRequest) returns (Empty);
rpc GetPermission(GetPermissionRequest) returns (PermissionResponse);
rpc ListPermissions(ListPermissionsRequest) returns (PermissionListResponse);
rpc RemovePermission(RemovePermissionRequest) returns (Empty);

message SetPermissionRequest {
  ResourceRef resource = 1;
  ActorRef actor = 2;
  Role role = 3;
}

message GetPermissionRequest {
  ResourceRef resource = 1;
  ActorRef actor = 2;
}

message ListPermissionsRequest {
  ResourceRef resource = 1;
  optional ActorType actor_type_filter = 2;  // Filter by actor type
}

message RemovePermissionRequest {
  ResourceRef resource = 1;
  ActorRef actor = 2;
}

message PermissionListResponse {
  repeated PermissionEntry permissions = 1;
}

message PermissionEntry {
  ActorRef actor = 1;
  Role role = 2;
  string actor_display_name = 3;  // Human-readable name
}
```

**Savings:** 32 methods eliminated

---

### 2. Unified CRUD Pattern for Organizations (18 → 8 methods)

Organization-related methods follow a pattern that can be slightly consolidated.

**Current (18 methods):**
- Organizations CRUD: 5 methods
- Organization Members: 5 methods  
- Organization Invites: 5 methods
- Organization Workspaces: 3 methods

**Proposed (8 methods):**
```protobuf
// Organizations (keep as-is, already optimal)
rpc CreateOrganization(...) returns (Organization);
rpc GetOrganization(...) returns (Organization);
rpc ListUserOrganizations(Empty) returns (OrganizationList);
rpc UpdateOrganization(...) returns (Organization);
rpc DeleteOrganization(...) returns (Empty);

// Organization Members (merge Add/Update into UpsertMember)
rpc UpsertOrganizationMember(...) returns (OrganizationMember);  // Replaces Add + UpdateRole
rpc GetOrganizationMember(...) returns (OrganizationMember);
rpc ListOrganizationMembers(...) returns (OrganizationMemberList);
rpc RemoveOrganizationMember(...) returns (Empty);

// Organization Invites (keep as-is, Accept is distinct from CRUD)
rpc CreateOrganizationInvite(...) returns (OrganizationInvite);
rpc GetOrganizationInvite(...) returns (OrganizationInvite);
rpc ListOrganizationInvites(...) returns (OrganizationInviteList);
rpc AcceptOrganizationInvite(...) returns (OrganizationMember);
rpc DeleteOrganizationInvite(...) returns (Empty);

// Organization Workspaces (keep as-is)
rpc LinkWorkspaceToOrganization(...) returns (Empty);
rpc UnlinkWorkspaceFromOrganization(...) returns (Empty);
rpc ListOrganizationWorkspaces(...) returns (WorkspaceList);
```

**Savings:** 1 method (AddOrganizationMember + UpdateOrganizationMemberRole → UpsertOrganizationMember)

*Note: This category is already fairly lean. Major gains come from permissions.*

---

### 3. Merge Audit Log Methods (3 → 2 methods)

**Current:**
```protobuf
rpc ListAuditLogs(...) returns (AuditLogList);
rpc GetAuditLog(...) returns (AuditLogEntry);
rpc CountAuditLogs(...) returns (CountAuditLogsResponse);
```

**Proposed:** Merge Count into List response
```protobuf
rpc ListAuditLogs(...) returns (AuditLogList);  // Include total_count in response (already there!)
rpc GetAuditLog(...) returns (AuditLogEntry);

message AuditLogList {
  repeated AuditLogEntry entries = 1;
  uint64 total_count = 2;  // Already exists, Count method is redundant
}
```

**Savings:** 1 method (CountAuditLogs is redundant)

---

### 4. Consider Batch Operations (Future)

Not proposing immediate changes, but future consideration:

```protobuf
// Batch secret operations
rpc BatchUpsertSecrets(BatchUpsertSecretsRequest) returns (BatchUpsertSecretsResponse);
rpc BatchDeleteSecrets(BatchDeleteSecretsRequest) returns (Empty);

// This would reduce client round-trips for bulk operations
// but adds complexity. Defer to a future RFC.
```

---

## Consolidated API Summary

### Methods After Consolidation: 47 Methods

| Category | Before | After | Change |
|----------|--------|-------|--------|
| Auth & Email | 5 | 5 | 0 |
| Workspaces | 4 | 4 | 0 |
| Invites | 4 | 4 | 0 |
| Principals | 6 | 6 | 0 |
| Principal Export | 3 | 3 | 0 |
| Projects | 4 | 4 | 0 |
| Environments | 4 | 4 | 0 |
| Secrets | 4 | 4 | 0 |
| Watch | 1 | 1 | 0 |
| **Permissions** | **36** | **4** | **-32** |
| Groups CRUD | 5 | 5 | 0 |
| Group Membership | 4 | 4 | 0 |
| Effective Permissions | 1 | 1 | 0 |
| Audit Logs | 3 | 2 | -1 |
| Organizations | 5 | 5 | 0 |
| Org Members | 5 | 4 | -1 |
| Org Invites | 5 | 5 | 0 |
| Org Workspaces | 3 | 3 | 0 |
| Billing | 4 | 4 | 0 |
| **TOTAL** | **106** | **72** | **-34** |

Wait, let me recount more carefully...

### Accurate Count

**Keeping (unchanged):**
- Auth & Email: 5
- Workspaces: 4
- Invites: 4
- Principals: 6
- Principal Export: 3
- Projects: 4
- Environments: 4
- Secrets: 4
- Watch: 1
- Groups CRUD: 5
- Group Membership: 4
- Effective Permissions: 1
- Audit Logs: 2 (was 3)
- Organizations: 5
- Org Members: 4 (was 5)
- Org Invites: 5
- Org Workspaces: 3
- Billing: 4
- **Generic Permissions: 4** (replaces 36)

**Subtotal:** 72 methods

This gives us **72 methods** (32% reduction), not quite the <50 target.

---

## Aggressive Consolidation (Target: <50)

To hit <50 methods, we need to be more aggressive:

### Additional Consolidation Options

#### Option A: Generic Resource CRUD (Projects + Environments)

```protobuf
enum EntityType {
  ENTITY_PROJECT = 0;
  ENTITY_ENVIRONMENT = 1;
}

// Generic CRUD for hierarchical resources
rpc CreateEntity(CreateEntityRequest) returns (Entity);
rpc GetEntity(GetEntityRequest) returns (Entity);
rpc ListEntities(ListEntitiesRequest) returns (EntityList);
rpc DeleteEntity(DeleteEntityRequest) returns (Empty);
```

**Savings:** 4 methods (8 → 4)

#### Option B: Merge Invite Patterns (Workspace + Org Invites)

```protobuf
enum InviteScope {
  INVITE_WORKSPACE = 0;
  INVITE_ORGANIZATION = 1;
}

rpc CreateInvite(CreateInviteRequest) returns (Invite);
rpc GetInvite(GetInviteRequest) returns (Invite);
rpc ListInvites(ListInvitesRequest) returns (InviteList);
rpc RevokeInvite(RevokeInviteRequest) returns (Empty);
rpc AcceptInvite(AcceptInviteRequest) returns (AcceptInviteResponse);
```

**Savings:** 4 methods (9 → 5)

#### Option C: Unified Member Management

```protobuf
enum MembershipScope {
  MEMBERSHIP_GROUP = 0;
  MEMBERSHIP_ORGANIZATION = 1;
}

rpc AddMember(AddMemberRequest) returns (Member);
rpc GetMember(GetMemberRequest) returns (Member);
rpc ListMembers(ListMembersRequest) returns (MemberList);
rpc UpdateMember(UpdateMemberRequest) returns (Member);
rpc RemoveMember(RemoveMemberRequest) returns (Empty);
```

**Savings:** 4 methods (9 → 5)

### Aggressive Consolidation Summary

| Change | Before | After | Savings |
|--------|--------|-------|---------|
| Base (with generic permissions) | 106 | 72 | 34 |
| + Generic entities (Option A) | 72 | 68 | 4 |
| + Unified invites (Option B) | 68 | 64 | 4 |
| + Unified members (Option C) | 64 | 60 | 4 |
| **Total with all options** | **106** | **60** | **46** |

Still not quite <50. To reach that:

#### Option D: Merge Group + Principal management

Groups and Principals are different concepts, but their CRUD patterns are similar:

```protobuf
// This is probably TOO aggressive - losing semantic clarity
```

**Recommendation:** Stop at 60 methods. Going below 50 sacrifices semantic clarity for marginal gains.

---

## Recommended Approach: 60 Methods

Apply these changes:
1. ✅ Generic permission methods (36 → 4) — **-32 methods**
2. ✅ Remove redundant CountAuditLogs — **-1 method**  
3. ✅ Merge Org member add/update — **-1 method**
4. ✅ Generic entity CRUD (Project/Env) — **-4 methods**
5. ✅ Unified invite pattern — **-4 methods**
6. ✅ Unified member management — **-4 methods**

**Final count: 60 methods (43% reduction)**

---

## Breaking Change Assessment

### High Impact (Requires All Clients to Update)

| Change | Impact | Mitigation |
|--------|--------|------------|
| Generic permissions | All permission operations change | Provide migration script, deprecate old methods for 2 versions |
| Unified invites | Workspace + org invite clients affected | Same proto shape with scope enum |

### Medium Impact

| Change | Impact | Mitigation |
|--------|--------|------------|
| Generic entities | Project/Env CRUD callers | Wrapper type is similar |
| Unified members | Group + org member callers | Similar pattern |

### Low Impact

| Change | Impact | Mitigation |
|--------|--------|------------|
| Remove CountAuditLogs | Callers of this specific method | Already available in ListAuditLogs response |
| Merge org member methods | Callers of Add+UpdateRole | Upsert is idempotent superset |

---

## Migration Path

### Phase 1: Add New Methods (v0.X)
- Add generic permission methods alongside existing ones
- Add new unified methods
- Mark old methods as deprecated in proto comments
- Update CLI to use new methods

### Phase 2: Deprecation Warning (v0.X+1)
- Server logs warnings when deprecated methods called
- Add runtime deprecation headers to gRPC responses
- Documentation updated to prefer new methods

### Phase 3: Remove Old Methods (v1.0)
- Remove all deprecated methods
- Breaking change, major version bump
- Clear upgrade guide published

### Client Migration Example

**Before (old API):**
```rust
client.set_user_project_permission(SetUserProjectPermissionRequest {
    workspace_name: "acme".into(),
    project_name: "api".into(),
    user_email: "alice@example.com".into(),
    role: Role::Write,
})
```

**After (new API):**
```rust
client.set_permission(SetPermissionRequest {
    resource: Some(ResourceRef {
        r#type: ResourceType::Project as i32,
        workspace_name: "acme".into(),
        project_name: Some("api".into()),
        environment_name: None,
    }),
    actor: Some(ActorRef {
        r#type: ActorType::User as i32,
        actor: Some(actor_ref::Actor::UserEmail("alice@example.com".into())),
    }),
    role: Role::Write as i32,
})
```

---

## Implementation Notes

### Server-Side

1. **Routing:** New generic methods dispatch to existing storage layer
2. **Validation:** Validate resource/actor combinations (e.g., env requires project)
3. **Backward compat:** Old methods can internally call new generic handlers

### Client-Side (CLI)

1. **Abstraction:** CLI already uses high-level commands; internal calls change
2. **No user-facing changes** for the consolidation itself

### Proto Organization

Consider splitting `zopp.proto` into:
- `zopp/v1/auth.proto`
- `zopp/v1/resources.proto`
- `zopp/v1/permissions.proto`
- `zopp/v1/organizations.proto`
- `zopp/v1/billing.proto`

This doesn't reduce methods but improves maintainability.

---

## Decision Matrix

| Approach | Methods | Reduction | Complexity | Recommended |
|----------|---------|-----------|------------|-------------|
| Status quo | 106 | 0% | Low | ❌ |
| Permissions only | 74 | 30% | Low | ✅ Good start |
| + Audit/Org tweaks | 72 | 32% | Low | ✅ |
| + Entities/Invites/Members | 60 | 43% | Medium | ✅ **Recommended** |
| Aggressive (<50) | ~48 | 55% | High | ❌ Over-abstraction |

---

## Conclusion

**Recommendation:** Consolidate to **60 methods** (43% reduction).

The primary win comes from generic permission methods (32 methods eliminated). Additional gains from unified patterns bring us to 60 methods without sacrificing API clarity.

Going below 50 methods requires aggressive abstractions that hurt developer experience and semantic clarity. The 60-method target achieves the goal of a manageable API surface while maintaining intuitive, purpose-driven endpoints.

### Next Steps

1. [ ] Review and approve this RFC
2. [ ] Implement generic permission types in proto
3. [ ] Add new methods alongside deprecated ones
4. [ ] Migrate CLI to new methods
5. [ ] Release with deprecation warnings
6. [ ] Remove old methods in next major version
