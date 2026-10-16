use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum RoleType {
    /// Administrator role with full privileges
    Admin,
    /// Regular user role with limited privileges
    User,
}

impl std::fmt::Display for RoleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoleType::Admin => write!(f, "Admin"),
            RoleType::User => write!(f, "User"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInfo {
    /// Application username (used for authentication)
    pub username: String,
    /// Operating system user account (used for command execution)
    pub os_user: String,
    /// Role/privilege level of the user
    pub role: RoleType,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AdminCommand {
    /// Open/access the admin panel
    Open,
    /// Request the add user form for a specific username
    GetAddUserForm { username: String },
    /// Submit completed add user form with user details
    SendAddUserForm {
        username: String,
        password: String,
        os_user: String,
        role: RoleType,
    },
    /// Remove an existing user
    RemoveUser { username: String },
    /// List all users in the system
    ListUsers,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AdminCommandResult {
    Open {
        success: bool,
    },
    /// Infos needed to display the add user form with available OS users on client
    GetAddUserForm {
        success: bool,
        os_users: Vec<(u16, String)>,
        username: String,
    },
    SendAddUserForm {
        success: bool,
    },
    RemoveUser {
        success: bool,
    },
    ListUsers {
        success: bool,
        users: Vec<UserInfo>,
    },
}
