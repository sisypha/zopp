//! Handler modules for gRPC service implementation
//!
//! This module contains handler functions organized by domain:
//! - auth: join, register, login
//! - verification: email verification for new principals
//! - workspaces: create, list, get_keys
//! - invites: create, get, list, revoke
//! - principals: get, rename, list, service principals, remove, revoke, effective permissions
//! - projects: create, list, get, delete
//! - environments: create, list, get, delete
//! - secrets: upsert, get, list, delete, watch
//! - permissions: principal permissions at workspace/project/environment levels
//! - groups: group CRUD + membership
//! - group_permissions: group permissions at all levels
//! - user_permissions: user permissions at all levels
//! - audit: audit log queries

pub mod audit;
pub mod auth;
pub mod environments;
pub mod group_permissions;
pub mod groups;
pub mod invites;
pub mod permissions;
pub mod principals;
pub mod projects;
pub mod secrets;
pub mod user_permissions;
pub mod verification;
pub mod workspaces;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::server::ZoppServer;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_proto::*;

#[tonic::async_trait]
impl ZoppService for ZoppServer {
    // ───────────────────────────────────── Auth ─────────────────────────────────────

    async fn join(&self, request: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        auth::join(self, request).await
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        auth::register(self, request).await
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        auth::login(self, request).await
    }

    // ───────────────────────────────────── Email Verification ─────────────────────────────────────

    async fn verify_email(
        &self,
        request: Request<VerifyEmailRequest>,
    ) -> Result<Response<VerifyEmailResponse>, Status> {
        verification::verify_email(self, request).await
    }

    async fn resend_verification(
        &self,
        request: Request<ResendVerificationRequest>,
    ) -> Result<Response<ResendVerificationResponse>, Status> {
        verification::resend_verification(self, request).await
    }

    // ───────────────────────────────────── Workspaces ─────────────────────────────────────

    async fn create_workspace(
        &self,
        request: Request<CreateWorkspaceRequest>,
    ) -> Result<Response<Workspace>, Status> {
        workspaces::create_workspace(self, request).await
    }

    async fn list_workspaces(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<WorkspaceList>, Status> {
        workspaces::list_workspaces(self, request).await
    }

    async fn get_workspace_keys(
        &self,
        request: Request<GetWorkspaceKeysRequest>,
    ) -> Result<Response<WorkspaceKeys>, Status> {
        workspaces::get_workspace_keys(self, request).await
    }

    async fn grant_principal_workspace_access(
        &self,
        request: Request<GrantPrincipalWorkspaceAccessRequest>,
    ) -> Result<Response<Empty>, Status> {
        workspaces::grant_principal_workspace_access(self, request).await
    }

    // ───────────────────────────────────── Invites ─────────────────────────────────────

    async fn create_invite(
        &self,
        request: Request<CreateInviteRequest>,
    ) -> Result<Response<InviteToken>, Status> {
        invites::create_invite(self, request).await
    }

    async fn get_invite(
        &self,
        request: Request<GetInviteRequest>,
    ) -> Result<Response<InviteToken>, Status> {
        invites::get_invite(self, request).await
    }

    async fn list_invites(&self, request: Request<Empty>) -> Result<Response<InviteList>, Status> {
        invites::list_invites(self, request).await
    }

    async fn revoke_invite(
        &self,
        request: Request<RevokeInviteRequest>,
    ) -> Result<Response<Empty>, Status> {
        invites::revoke_invite(self, request).await
    }

    // ───────────────────────────────────── Principals ─────────────────────────────────────

    async fn get_principal(
        &self,
        request: Request<GetPrincipalRequest>,
    ) -> Result<Response<Principal>, Status> {
        principals::get_principal(self, request).await
    }

    async fn rename_principal(
        &self,
        request: Request<RenamePrincipalRequest>,
    ) -> Result<Response<Empty>, Status> {
        principals::rename_principal(self, request).await
    }

    async fn list_principals(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<PrincipalList>, Status> {
        principals::list_principals(self, request).await
    }

    async fn list_workspace_service_principals(
        &self,
        request: Request<ListWorkspaceServicePrincipalsRequest>,
    ) -> Result<Response<ServicePrincipalList>, Status> {
        principals::list_workspace_service_principals(self, request).await
    }

    async fn remove_principal_from_workspace(
        &self,
        request: Request<RemovePrincipalFromWorkspaceRequest>,
    ) -> Result<Response<Empty>, Status> {
        principals::remove_principal_from_workspace(self, request).await
    }

    async fn revoke_all_principal_permissions(
        &self,
        request: Request<RevokeAllPrincipalPermissionsRequest>,
    ) -> Result<Response<RevokeAllPrincipalPermissionsResponse>, Status> {
        principals::revoke_all_principal_permissions(self, request).await
    }

    async fn get_effective_permissions(
        &self,
        request: Request<GetEffectivePermissionsRequest>,
    ) -> Result<Response<EffectivePermissionsResponse>, Status> {
        principals::get_effective_permissions(self, request).await
    }

    // ───────────────────────────────────── Principal Export/Import ─────────────────────────────────────

    async fn create_principal_export(
        &self,
        request: Request<CreatePrincipalExportRequest>,
    ) -> Result<Response<CreatePrincipalExportResponse>, Status> {
        principals::create_principal_export(self, request).await
    }

    async fn get_principal_export(
        &self,
        request: Request<GetPrincipalExportRequest>,
    ) -> Result<Response<GetPrincipalExportResponse>, Status> {
        principals::get_principal_export(self, request).await
    }

    async fn consume_principal_export(
        &self,
        request: Request<ConsumePrincipalExportRequest>,
    ) -> Result<Response<Empty>, Status> {
        principals::consume_principal_export(self, request).await
    }

    // ───────────────────────────────────── Projects ─────────────────────────────────────

    async fn create_project(
        &self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<Project>, Status> {
        projects::create_project(self, request).await
    }

    async fn list_projects(
        &self,
        request: Request<ListProjectsRequest>,
    ) -> Result<Response<ProjectList>, Status> {
        projects::list_projects(self, request).await
    }

    async fn get_project(
        &self,
        request: Request<GetProjectRequest>,
    ) -> Result<Response<Project>, Status> {
        projects::get_project(self, request).await
    }

    async fn delete_project(
        &self,
        request: Request<DeleteProjectRequest>,
    ) -> Result<Response<Empty>, Status> {
        projects::delete_project(self, request).await
    }

    // ───────────────────────────────────── Environments ─────────────────────────────────────

    async fn create_environment(
        &self,
        request: Request<CreateEnvironmentRequest>,
    ) -> Result<Response<Environment>, Status> {
        environments::create_environment(self, request).await
    }

    async fn list_environments(
        &self,
        request: Request<ListEnvironmentsRequest>,
    ) -> Result<Response<EnvironmentList>, Status> {
        environments::list_environments(self, request).await
    }

    async fn get_environment(
        &self,
        request: Request<GetEnvironmentRequest>,
    ) -> Result<Response<Environment>, Status> {
        environments::get_environment(self, request).await
    }

    async fn delete_environment(
        &self,
        request: Request<DeleteEnvironmentRequest>,
    ) -> Result<Response<Empty>, Status> {
        environments::delete_environment(self, request).await
    }

    // ───────────────────────────────────── Secrets ─────────────────────────────────────

    async fn upsert_secret(
        &self,
        request: Request<UpsertSecretRequest>,
    ) -> Result<Response<Empty>, Status> {
        secrets::upsert_secret(self, request).await
    }

    async fn get_secret(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<Secret>, Status> {
        secrets::get_secret(self, request).await
    }

    async fn list_secrets(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<SecretList>, Status> {
        secrets::list_secrets(self, request).await
    }

    async fn delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<Empty>, Status> {
        secrets::delete_secret(self, request).await
    }

    type WatchSecretsStream = ReceiverStream<Result<WatchSecretsResponse, Status>>;

    async fn watch_secrets(
        &self,
        request: Request<WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        secrets::watch_secrets(self, request).await
    }

    // ───────────────────────────────────── Principal Permissions ─────────────────────────────────────

    async fn set_workspace_permission(
        &self,
        request: Request<SetWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        permissions::set_workspace_permission(self, request).await
    }

    async fn get_workspace_permission(
        &self,
        request: Request<GetWorkspacePermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        permissions::get_workspace_permission(self, request).await
    }

    async fn list_workspace_permissions(
        &self,
        request: Request<ListWorkspacePermissionsRequest>,
    ) -> Result<Response<PermissionList>, Status> {
        permissions::list_workspace_permissions(self, request).await
    }

    async fn remove_workspace_permission(
        &self,
        request: Request<RemoveWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        permissions::remove_workspace_permission(self, request).await
    }

    async fn set_project_permission(
        &self,
        request: Request<SetProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        permissions::set_project_permission(self, request).await
    }

    async fn get_project_permission(
        &self,
        request: Request<GetProjectPermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        permissions::get_project_permission(self, request).await
    }

    async fn list_project_permissions(
        &self,
        request: Request<ListProjectPermissionsRequest>,
    ) -> Result<Response<PermissionList>, Status> {
        permissions::list_project_permissions(self, request).await
    }

    async fn remove_project_permission(
        &self,
        request: Request<RemoveProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        permissions::remove_project_permission(self, request).await
    }

    async fn set_environment_permission(
        &self,
        request: Request<SetEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        permissions::set_environment_permission(self, request).await
    }

    async fn get_environment_permission(
        &self,
        request: Request<GetEnvironmentPermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        permissions::get_environment_permission(self, request).await
    }

    async fn list_environment_permissions(
        &self,
        request: Request<ListEnvironmentPermissionsRequest>,
    ) -> Result<Response<PermissionList>, Status> {
        permissions::list_environment_permissions(self, request).await
    }

    async fn remove_environment_permission(
        &self,
        request: Request<RemoveEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        permissions::remove_environment_permission(self, request).await
    }

    // ───────────────────────────────────── Groups ─────────────────────────────────────

    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<Group>, Status> {
        groups::create_group(self, request).await
    }

    async fn get_group(
        &self,
        request: Request<GetGroupRequest>,
    ) -> Result<Response<Group>, Status> {
        groups::get_group(self, request).await
    }

    async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<GroupList>, Status> {
        groups::list_groups(self, request).await
    }

    async fn update_group(
        &self,
        request: Request<UpdateGroupRequest>,
    ) -> Result<Response<Group>, Status> {
        groups::update_group(self, request).await
    }

    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<Empty>, Status> {
        groups::delete_group(self, request).await
    }

    async fn add_group_member(
        &self,
        request: Request<AddGroupMemberRequest>,
    ) -> Result<Response<Empty>, Status> {
        groups::add_group_member(self, request).await
    }

    async fn remove_group_member(
        &self,
        request: Request<RemoveGroupMemberRequest>,
    ) -> Result<Response<Empty>, Status> {
        groups::remove_group_member(self, request).await
    }

    async fn list_group_members(
        &self,
        request: Request<ListGroupMembersRequest>,
    ) -> Result<Response<GroupMemberList>, Status> {
        groups::list_group_members(self, request).await
    }

    async fn list_user_groups(
        &self,
        request: Request<ListUserGroupsRequest>,
    ) -> Result<Response<GroupList>, Status> {
        groups::list_user_groups(self, request).await
    }

    // ───────────────────────────────────── Group Permissions ─────────────────────────────────────

    async fn set_group_workspace_permission(
        &self,
        request: Request<SetGroupWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        group_permissions::set_group_workspace_permission(self, request).await
    }

    async fn get_group_workspace_permission(
        &self,
        request: Request<GetGroupWorkspacePermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        group_permissions::get_group_workspace_permission(self, request).await
    }

    async fn list_group_workspace_permissions(
        &self,
        request: Request<ListGroupWorkspacePermissionsRequest>,
    ) -> Result<Response<GroupPermissionList>, Status> {
        group_permissions::list_group_workspace_permissions(self, request).await
    }

    async fn remove_group_workspace_permission(
        &self,
        request: Request<RemoveGroupWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        group_permissions::remove_group_workspace_permission(self, request).await
    }

    async fn set_group_project_permission(
        &self,
        request: Request<SetGroupProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        group_permissions::set_group_project_permission(self, request).await
    }

    async fn get_group_project_permission(
        &self,
        request: Request<GetGroupProjectPermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        group_permissions::get_group_project_permission(self, request).await
    }

    async fn list_group_project_permissions(
        &self,
        request: Request<ListGroupProjectPermissionsRequest>,
    ) -> Result<Response<GroupPermissionList>, Status> {
        group_permissions::list_group_project_permissions(self, request).await
    }

    async fn remove_group_project_permission(
        &self,
        request: Request<RemoveGroupProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        group_permissions::remove_group_project_permission(self, request).await
    }

    async fn set_group_environment_permission(
        &self,
        request: Request<SetGroupEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        group_permissions::set_group_environment_permission(self, request).await
    }

    async fn get_group_environment_permission(
        &self,
        request: Request<GetGroupEnvironmentPermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        group_permissions::get_group_environment_permission(self, request).await
    }

    async fn list_group_environment_permissions(
        &self,
        request: Request<ListGroupEnvironmentPermissionsRequest>,
    ) -> Result<Response<GroupPermissionList>, Status> {
        group_permissions::list_group_environment_permissions(self, request).await
    }

    async fn remove_group_environment_permission(
        &self,
        request: Request<RemoveGroupEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        group_permissions::remove_group_environment_permission(self, request).await
    }

    // ───────────────────────────────────── User Permissions ─────────────────────────────────────

    async fn set_user_workspace_permission(
        &self,
        request: Request<SetUserWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_permissions::set_user_workspace_permission(self, request).await
    }

    async fn get_user_workspace_permission(
        &self,
        request: Request<GetUserWorkspacePermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        user_permissions::get_user_workspace_permission(self, request).await
    }

    async fn list_user_workspace_permissions(
        &self,
        request: Request<ListUserWorkspacePermissionsRequest>,
    ) -> Result<Response<UserPermissionList>, Status> {
        user_permissions::list_user_workspace_permissions(self, request).await
    }

    async fn remove_user_workspace_permission(
        &self,
        request: Request<RemoveUserWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_permissions::remove_user_workspace_permission(self, request).await
    }

    async fn set_user_project_permission(
        &self,
        request: Request<SetUserProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_permissions::set_user_project_permission(self, request).await
    }

    async fn get_user_project_permission(
        &self,
        request: Request<GetUserProjectPermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        user_permissions::get_user_project_permission(self, request).await
    }

    async fn list_user_project_permissions(
        &self,
        request: Request<ListUserProjectPermissionsRequest>,
    ) -> Result<Response<UserPermissionList>, Status> {
        user_permissions::list_user_project_permissions(self, request).await
    }

    async fn remove_user_project_permission(
        &self,
        request: Request<RemoveUserProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_permissions::remove_user_project_permission(self, request).await
    }

    async fn set_user_environment_permission(
        &self,
        request: Request<SetUserEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_permissions::set_user_environment_permission(self, request).await
    }

    async fn get_user_environment_permission(
        &self,
        request: Request<GetUserEnvironmentPermissionRequest>,
    ) -> Result<Response<PermissionResponse>, Status> {
        user_permissions::get_user_environment_permission(self, request).await
    }

    async fn list_user_environment_permissions(
        &self,
        request: Request<ListUserEnvironmentPermissionsRequest>,
    ) -> Result<Response<UserPermissionList>, Status> {
        user_permissions::list_user_environment_permissions(self, request).await
    }

    async fn remove_user_environment_permission(
        &self,
        request: Request<RemoveUserEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_permissions::remove_user_environment_permission(self, request).await
    }

    // ───────────────────────────────────── Audit Logs ─────────────────────────────────────

    async fn list_audit_logs(
        &self,
        request: Request<ListAuditLogsRequest>,
    ) -> Result<Response<AuditLogList>, Status> {
        audit::list_audit_logs(self, request).await
    }

    async fn get_audit_log(
        &self,
        request: Request<GetAuditLogRequest>,
    ) -> Result<Response<AuditLogEntry>, Status> {
        audit::get_audit_log(self, request).await
    }

    async fn count_audit_logs(
        &self,
        request: Request<CountAuditLogsRequest>,
    ) -> Result<Response<CountAuditLogsResponse>, Status> {
        audit::count_audit_logs(self, request).await
    }

    // ───────────────────────────────────── Organizations ─────────────────────────────────────

    async fn create_organization(
        &self,
        _request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<Organization>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn get_organization(
        &self,
        _request: Request<GetOrganizationRequest>,
    ) -> Result<Response<Organization>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn list_user_organizations(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OrganizationList>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn update_organization(
        &self,
        _request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<Organization>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn delete_organization(
        &self,
        _request: Request<DeleteOrganizationRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    // ───────────────────────────────────── Organization Members ─────────────────────────────────────

    async fn add_organization_member(
        &self,
        _request: Request<AddOrganizationMemberRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn get_organization_member(
        &self,
        _request: Request<GetOrganizationMemberRequest>,
    ) -> Result<Response<OrganizationMember>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn list_organization_members(
        &self,
        _request: Request<ListOrganizationMembersRequest>,
    ) -> Result<Response<OrganizationMemberList>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn update_organization_member_role(
        &self,
        _request: Request<UpdateOrganizationMemberRoleRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn remove_organization_member(
        &self,
        _request: Request<RemoveOrganizationMemberRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    // ───────────────────────────────────── Organization Invites ─────────────────────────────────────

    async fn create_organization_invite(
        &self,
        _request: Request<CreateOrganizationInviteRequest>,
    ) -> Result<Response<OrganizationInvite>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn get_organization_invite(
        &self,
        _request: Request<GetOrganizationInviteRequest>,
    ) -> Result<Response<OrganizationInvite>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn list_organization_invites(
        &self,
        _request: Request<ListOrganizationInvitesRequest>,
    ) -> Result<Response<OrganizationInviteList>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn accept_organization_invite(
        &self,
        _request: Request<AcceptOrganizationInviteRequest>,
    ) -> Result<Response<OrganizationMember>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn delete_organization_invite(
        &self,
        _request: Request<DeleteOrganizationInviteRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    // ───────────────────────────────────── Organization Workspaces ─────────────────────────────────────

    async fn link_workspace_to_organization(
        &self,
        _request: Request<LinkWorkspaceToOrganizationRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn unlink_workspace_from_organization(
        &self,
        _request: Request<UnlinkWorkspaceFromOrganizationRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    async fn list_organization_workspaces(
        &self,
        _request: Request<ListOrganizationWorkspacesRequest>,
    ) -> Result<Response<WorkspaceList>, Status> {
        Err(Status::unimplemented(
            "Organization support not yet implemented",
        ))
    }

    // ───────────────────────────────────── Billing ─────────────────────────────────────

    async fn get_subscription(
        &self,
        _request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<Subscription>, Status> {
        Err(Status::unimplemented("Billing support not yet implemented"))
    }

    async fn list_payments(
        &self,
        _request: Request<ListPaymentsRequest>,
    ) -> Result<Response<PaymentList>, Status> {
        Err(Status::unimplemented("Billing support not yet implemented"))
    }

    async fn create_checkout_session(
        &self,
        _request: Request<CreateCheckoutSessionRequest>,
    ) -> Result<Response<CheckoutSession>, Status> {
        Err(Status::unimplemented("Billing support not yet implemented"))
    }

    async fn create_billing_portal_session(
        &self,
        _request: Request<CreateBillingPortalSessionRequest>,
    ) -> Result<Response<BillingPortalSession>, Status> {
        Err(Status::unimplemented("Billing support not yet implemented"))
    }
}
