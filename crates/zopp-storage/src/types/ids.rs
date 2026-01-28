//! Strongly-typed identifiers (avoid mixing strings/UUIDs arbitrarily).

use uuid::Uuid;

/// User identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId(pub Uuid);

/// Principal (device/service account) identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalId(pub Uuid);

/// Invite identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InviteId(pub Uuid);

/// Workspace identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceId(pub Uuid);

/// Project identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectId(pub Uuid);

/// Project name wrapper.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectName(pub String);

/// Environment identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnvironmentId(pub Uuid);

/// Environment name wrapper.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnvName(pub String);

/// Group identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupId(pub Uuid);

/// Principal export identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalExportId(pub Uuid);

/// Email verification identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EmailVerificationId(pub Uuid);

/// Organization identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrganizationId(pub Uuid);

/// Organization invite identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrganizationInviteId(pub Uuid);

/// Subscription identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub Uuid);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_debug() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        assert!(format!("{:?}", user_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_principal_id_debug() {
        let uuid = Uuid::new_v4();
        let principal_id = PrincipalId(uuid);
        assert!(format!("{:?}", principal_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_workspace_id_debug() {
        let uuid = Uuid::new_v4();
        let workspace_id = WorkspaceId(uuid);
        assert!(format!("{:?}", workspace_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_project_id_debug() {
        let uuid = Uuid::new_v4();
        let project_id = ProjectId(uuid);
        assert!(format!("{:?}", project_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_environment_id_debug() {
        let uuid = Uuid::new_v4();
        let env_id = EnvironmentId(uuid);
        assert!(format!("{:?}", env_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_group_id_debug() {
        let uuid = Uuid::new_v4();
        let group_id = GroupId(uuid);
        assert!(format!("{:?}", group_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_typed_ids_equality() {
        let uuid = Uuid::new_v4();
        let user_id1 = UserId(uuid);
        let user_id2 = UserId(uuid);
        assert_eq!(user_id1, user_id2);

        let different_uuid = Uuid::new_v4();
        let user_id3 = UserId(different_uuid);
        assert_ne!(user_id1, user_id3);
    }

    #[test]
    fn test_typed_ids_clone() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        let cloned = user_id.clone();
        assert_eq!(user_id, cloned);
    }

    #[test]
    fn test_typed_ids_inner_access() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        assert_eq!(user_id.0, uuid);

        let principal_id = PrincipalId(uuid);
        assert_eq!(principal_id.0, uuid);

        let workspace_id = WorkspaceId(uuid);
        assert_eq!(workspace_id.0, uuid);

        let project_id = ProjectId(uuid);
        assert_eq!(project_id.0, uuid);

        let env_id = EnvironmentId(uuid);
        assert_eq!(env_id.0, uuid);

        let group_id = GroupId(uuid);
        assert_eq!(group_id.0, uuid);
    }

    #[test]
    fn test_typed_ids_hash() {
        use std::collections::HashSet;

        let uuid = Uuid::new_v4();
        let user_id1 = UserId(uuid);
        let user_id2 = UserId(uuid);

        let mut set = HashSet::new();
        set.insert(user_id1);
        assert!(set.contains(&user_id2));
    }

    #[test]
    fn test_env_name_inner_access() {
        let name = EnvName("production".to_string());
        assert_eq!(name.0, "production");
    }

    #[test]
    fn test_project_name_inner_access() {
        let name = ProjectName("backend".to_string());
        assert_eq!(name.0, "backend");
    }

    #[test]
    fn test_env_name_equality() {
        let name1 = EnvName("production".to_string());
        let name2 = EnvName("production".to_string());
        let name3 = EnvName("staging".to_string());
        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_project_name_equality() {
        let name1 = ProjectName("backend".to_string());
        let name2 = ProjectName("backend".to_string());
        let name3 = ProjectName("frontend".to_string());
        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_invite_id_debug_and_equality() {
        let uuid = Uuid::new_v4();
        let invite_id1 = InviteId(uuid);
        let invite_id2 = InviteId(uuid);
        assert_eq!(invite_id1, invite_id2);
        assert!(format!("{:?}", invite_id1).contains(&uuid.to_string()));
    }
}
