use common::{
    admin::{AdminCommand, AdminCommandResult, RoleType, UserInfo},
    message::Request,
};

use crate::{SharedInput, next_input_line, response_handling::ResponseHandlingResult};

/// Handle results from admin panel commands executed on the server.
pub async fn handle_admin_panel_result(
    cmd_result: &AdminCommandResult,
    lines: &SharedInput,
) -> ResponseHandlingResult {
    match cmd_result {
        AdminCommandResult::Open { success } => {
            if *success {
                show_admin_panel();
            } else {
                println!("Admin panel access denied.");
            }
        }
        AdminCommandResult::GetAddUserForm {
            success,
            os_users,
            username,
        } => {
            if *success {
                return add_user_form(os_users, username, lines).await;
            } else {
                println!("Failed to retrieve add user form.");
            }
        }
        AdminCommandResult::SendAddUserForm { success } => {
            if *success {
                println!("User added successfully.");
            } else {
                println!("Failed to add user.");
            }
        }
        AdminCommandResult::RemoveUser { success } => {
            if *success {
                println!("User removed successfully.");
            } else {
                println!("Failed to remove user.");
            }
        }
        AdminCommandResult::ListUsers { success, users } => {
            if *success {
                show_user_list(users);
            } else {
                println!("Failed to retrieve user list.");
            }
        }
    }

    ResponseHandlingResult::None
}

pub fn show_admin_panel() {
    println!("\nAdmin panel:");
    println!("!list_users - List all users");
    println!("!add_user <username> - Add a new user");
    println!("!remove_user <username> - Remove a user");
}

/// Retrieve all necessary infos to add a new user.
pub async fn add_user_form(
    os_users: &Vec<(u16, String)>,
    username: &str,
    lines: &SharedInput,
) -> ResponseHandlingResult {
    let password: String;
    let os_user: String;
    let role: RoleType;

    println!("\nAdd user form:");
    println!("Username: {}", username);

    println!("Password: ");

    loop {
        match next_input_line(lines).await {
            Ok(Some(l)) => {
                println!("Password received. {}", l);
                password = l.trim().to_string();
                break;
            }
            _ => continue,
        };
    }

    println!("Confirm password: ");

    loop {
        match next_input_line(lines).await {
            Ok(Some(l)) => {
                if l.trim() == password {
                    break;
                } else {
                    println!("Passwords do not match. Canceling.");
                    return ResponseHandlingResult::None;
                }
            }
            _ => continue,
        };
    }

    println!("System user list:");
    for (id, name) in os_users {
        println!("- {}: {}", id, name);
    }

    println!("Enter the name of the system user to associate with this user: ");

    let os_users_names: Vec<String> = os_users.iter().map(|(_, name)| name.clone()).collect();

    loop {
        match next_input_line(lines).await {
            Ok(Some(l)) => {
                let l = l.trim().to_string();

                if os_users_names.contains(&l) {
                    os_user = l;
                    break;
                } else {
                    println!("Invalid user. Please enter a valid system user.");
                }
            }
            _ => continue,
        };
    }

    println!("Role (user/admin): ");

    loop {
        match next_input_line(lines).await {
            Ok(Some(l)) => {
                let l = l.trim().to_lowercase();

                if l == "user" {
                    role = RoleType::User;
                    break;
                } else if l == "admin" {
                    role = RoleType::Admin;
                    break;
                } else {
                    println!("Invalid role. Please enter 'user' or 'admin'.");
                }
            }
            _ => continue,
        };
    }

    if let RoleType::Admin = role {
        println!(
            "/!\\ You are about to create an admin user. This user will have full access to the system. Are you sure? (yes/no)"
        );

        loop {
            match next_input_line(lines).await {
                Ok(Some(l)) => {
                    let l = l.trim().to_lowercase();

                    if l == "yes" {
                        break;
                    } else if l == "no" {
                        println!("User creation canceled.");
                        return ResponseHandlingResult::None;
                    } else {
                        println!("Please enter 'yes' or 'no'.");
                    }
                }
                _ => continue,
            };
        }
    }

    ResponseHandlingResult::Request(Request::AdminPanel {
        cmd: AdminCommand::SendAddUserForm {
            username: username.to_string(),
            password,
            os_user,
            role,
        },
    })
}

pub fn show_user_list(users: &Vec<UserInfo>) {
    println!("\nUser list:");
    for user in users {
        println!("- {}:", user.username);
        println!("  OS User: {}", user.os_user);
        println!("  Role: {}", user.role);
    }
}
