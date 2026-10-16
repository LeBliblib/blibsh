use common::{
    admin::{AdminCommand, AdminCommandResult, RoleType, UserInfo},
    message::Response,
};

use crate::{
    authentication::AuthStatus,
    client::Client,
    password::hash_password,
    request_handling::RequestHandlingResult,
    user::{
        Role, User, delete_user, get_system_user_list, load_all_users, save_role, save_user,
        user_exists,
    },
};

/// Handle an admin command with permission checking.
pub fn handle_admin_command(cmd: &AdminCommand, cli: &mut Client) -> RequestHandlingResult {
    if cli.auth_status != AuthStatus::Authentified {
        return RequestHandlingResult::None;
    }

    match cmd {
        AdminCommand::Open => {
            if has_permission(cli) {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: AdminCommandResult::Open { success: true },
                })
            } else {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: AdminCommandResult::Open { success: false },
                })
            }
        }
        AdminCommand::GetAddUserForm { username } => {
            if has_permission(cli) {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: get_add_user_form(username.clone()),
                })
            } else {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: AdminCommandResult::GetAddUserForm {
                        success: false,
                        os_users: vec![],
                        username: username.clone(),
                    },
                })
            }
        }
        AdminCommand::SendAddUserForm {
            username,
            password,
            os_user,
            role,
        } => {
            if has_permission(cli) {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: validate_add_user_form(username, password, os_user, role),
                })
            } else {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: AdminCommandResult::SendAddUserForm { success: false },
                })
            }
        }
        AdminCommand::RemoveUser { username } => {
            if has_permission(cli) {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: remove_user(username),
                })
            } else {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: AdminCommandResult::RemoveUser { success: false },
                })
            }
        }
        AdminCommand::ListUsers => {
            if has_permission(cli) {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: list_users(),
                })
            } else {
                RequestHandlingResult::Response(Response::AdminPanel {
                    result: AdminCommandResult::ListUsers {
                        success: false,
                        users: vec![],
                    },
                })
            }
        }
    }
}

/// Check if the client has admin permissions.
pub fn has_permission(cli: &Client) -> bool {
    cli.role_data.is_some() && cli.role_data.as_ref().unwrap().role == RoleType::Admin
}

/// Retrieve the form data for adding a new user.
pub fn get_add_user_form(username: String) -> AdminCommandResult {
    if user_exists(&username) {
        return AdminCommandResult::GetAddUserForm {
            success: false,
            os_users: vec![],
            username: username,
        };
    }

    match get_system_user_list() {
        Ok(users) => AdminCommandResult::GetAddUserForm {
            success: true,
            os_users: users,
            username: username,
        },
        Err(_) => AdminCommandResult::GetAddUserForm {
            success: false,
            os_users: vec![],
            username: username,
        },
    }
}

/// Validate and create a new user from form data.
pub fn validate_add_user_form(
    username: &str,
    password: &str,
    os_user: &str,
    role: &RoleType,
) -> AdminCommandResult {
    if username.is_empty() || password.is_empty() || os_user.is_empty() {
        return AdminCommandResult::SendAddUserForm { success: false };
    }

    if user_exists(username) {
        return AdminCommandResult::SendAddUserForm { success: false };
    }

    if !matches!(role, RoleType::Admin | RoleType::User) {
        return AdminCommandResult::SendAddUserForm { success: false };
    }

    let hash = match hash_password(password) {
        Ok(hash) => hash,
        Err(_) => return AdminCommandResult::SendAddUserForm { success: false },
    };

    let user = User {
        id: username.to_string(),
        password_hash: hash,
        public_cert: vec![],
    };

    let role = Role {
        os_user: os_user.to_string(),
        role: role.clone(),
    };

    if let Err(_) = save_user(&user, true) {
        return AdminCommandResult::SendAddUserForm { success: false };
    }

    if let Err(_) = save_role(&user, &role, true) {
        return AdminCommandResult::SendAddUserForm { success: false };
    }

    AdminCommandResult::SendAddUserForm { success: true }
}

/// Remove an existing user from the server
pub fn remove_user(username: &str) -> AdminCommandResult {
    if username.is_empty() {
        return AdminCommandResult::RemoveUser { success: false };
    }

    delete_user(username);
    AdminCommandResult::RemoveUser { success: true }
}

/// List all users on the server (not os users).
pub fn list_users() -> AdminCommandResult {
    match load_all_users() {
        Ok(users) => AdminCommandResult::ListUsers {
            success: true,
            users: users
                .into_iter()
                .map(|(user, role)| UserInfo {
                    username: user.id,
                    os_user: role.os_user,
                    role: role.role,
                })
                .collect(),
        },
        Err(_) => AdminCommandResult::ListUsers {
            success: false,
            users: vec![],
        },
    }
}

mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn admin_panel_open_cmd() {
        // normal admin way
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::Admin);

        let cmd = AdminCommand::Open;
        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::Open { success: true },
            }) => assert!(true),
            r => assert!(false, "Expected a success, got {:?}", r),
        }

        // non-authentified admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::Admin);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }

        // non-admin user
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::Open { success: false },
            }) => assert!(true),
            r => assert!(false, "Expected a failure, got {:?}", r),
        }

        // non-authentified non-admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }
    }

    #[test]
    fn admin_panel_get_add_user_form_cmd() {
        // normal admin way
        // let mut cli = create_test_client(AuthStatus::Authentified, RoleType::Admin);

        let cmd = AdminCommand::GetAddUserForm {
            username: String::from("newuser"),
        };

        // We don't have correct file structures to test the success case.
        // match handle_admin_command(&cmd, &mut cli) {
        //     RequestHandlingResult::Response(Response::AdminPanel {
        //         result: AdminCommandResult::GetAddUserForm { success: true, .. },
        //     }) => assert!(true),
        //     r => assert!(false, "Expected a success, got {:?}", r),
        // }

        // non-authentified admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::Admin);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }

        // non-admin user
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::GetAddUserForm { success: false, .. },
            }) => assert!(true),
            r => assert!(false, "Expected a failure, got {:?}", r),
        }

        // non-authentified non-admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }
    }

    #[test]
    fn admin_panel_send_add_user_form_cmd() {
        // normal admin way
        // let mut cli = create_test_client(AuthStatus::Authentified, RoleType::Admin);

        let cmd = AdminCommand::SendAddUserForm {
            username: String::from("newuser"),
            password: String::from("password"),
            os_user: String::from("newuser"),
            role: RoleType::User,
        };

        // We don't have correct file structures to test the success case.
        // match handle_admin_command(&cmd, &mut cli) {
        //     RequestHandlingResult::Response(Response::AdminPanel {
        //         result: AdminCommandResult::SendAddUserForm { success: true, .. },
        //     }) => assert!(true),
        //     r => assert!(false, "Expected a success, got {:?}", r),
        // }

        // non-authentified admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::Admin);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }

        // non-admin user
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::SendAddUserForm { success: false, .. },
            }) => assert!(true),
            r => assert!(false, "Expected a failure, got {:?}", r),
        }

        // non-authentified non-admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }
    }

    #[test]
    fn admin_panel_remove_user_cmd() {
        // normal admin way
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::Admin);

        let cmd = AdminCommand::RemoveUser {
            username: String::from("newuser"),
        };

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::RemoveUser { success: true, .. },
            }) => assert!(true),
            r => assert!(false, "Expected a success, got {:?}", r),
        }

        // non-authentified admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::Admin);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }

        // non-admin user
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::RemoveUser { success: false, .. },
            }) => assert!(true),
            r => assert!(false, "Expected a failure, got {:?}", r),
        }

        // non-authentified non-admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }
    }

    #[test]
    fn admin_panel_list_users_cmd() {
        // normal admin way
        // let mut cli = create_test_client(AuthStatus::Authentified, RoleType::Admin);

        let cmd = AdminCommand::ListUsers;

        // We don't have correct file structures to test the success case.
        // match handle_admin_command(&cmd, &mut cli) {
        //     RequestHandlingResult::Response(Response::AdminPanel {
        //         result: AdminCommandResult::ListUsers { success: true, .. },
        //     }) => assert!(true),
        //     r => assert!(false, "Expected a success, got {:?}", r),
        // }

        // non-authentified admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::Admin);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }

        // non-admin user
        let mut cli = create_test_client(AuthStatus::Authentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::Response(Response::AdminPanel {
                result: AdminCommandResult::ListUsers { success: false, .. },
            }) => assert!(true),
            r => assert!(false, "Expected a failure, got {:?}", r),
        }

        // non-authentified non-admin
        let mut cli = create_test_client(AuthStatus::NotAuthentified, RoleType::User);

        match handle_admin_command(&cmd, &mut cli) {
            RequestHandlingResult::None => assert!(true),
            r => assert!(false, "Expected none, got {:?}", r),
        }
    }

    #[allow(dead_code)]
    fn create_test_client(auth_status: AuthStatus, role: RoleType) -> Client {
        Client {
            client_id: SocketAddr::from(([127, 0, 0, 1], 12345)),
            auth_status: auth_status,
            user_data: Some(User {
                id: String::from("test"),
                password_hash: String::from(""),
                public_cert: vec![],
            }),
            role_data: Some(Role {
                os_user: String::from("test"),
                role: role,
            }),
            shell_process: None,
            stdin: None,
            stdout: None,
            stderr: None,
            receiver_handle: None,
        }
    }
}
