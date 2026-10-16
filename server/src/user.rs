use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
};

use common::{
    admin::RoleType,
    message::Response,
    user::{UserCommand, UserCommandResult},
};
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncBufReadExt};

use crate::{
    authentication::AuthStatus, client::Client, password::hash_password,
    request_handling::RequestHandlingResult,
};

/// Path prefix for user data files
const USER_FILE_PATH: &str = "users/.user-";
/// Path prefix for role data files
const ROLE_FILE_PATH: &str = "roles/.role-";

/// User data stored on the server
#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    /// User's application username
    pub id: String,
    /// Argon2 hashed password
    pub password_hash: String,
    /// Public certificate for certificate-based authentication (PEM format)
    pub public_cert: Vec<u8>,
}

/// User role and OS account mapping.
#[derive(Serialize, Deserialize, Clone)]
pub struct Role {
    /// The OS user account to run commands as
    pub os_user: String,
    /// The user's role/privilege level
    pub role: RoleType,
}

/// Check if a user exists in the system.
pub fn user_exists(username: &str) -> bool {
    let user_path = format!("{}{}", USER_FILE_PATH, username);

    std::path::Path::new(&user_path).exists()
}

/// Load a user and their role information from storage.
pub fn load_user(user: &String) -> Result<(User, Role), std::io::Error> {
    let mut file = File::open(format!("{}{}", USER_FILE_PATH, user))?;

    let mut buf = vec![];
    let _ = file.read_to_end(&mut buf)?;

    let user_data = serde_json::from_slice::<User>(&buf)?;

    let mut role_file = File::open(format!("{}{}", ROLE_FILE_PATH, user))?;

    let mut role_buf = vec![];
    let _ = role_file.read_to_end(&mut role_buf)?;

    let role_data = serde_json::from_slice::<Role>(&role_buf)?;

    return Ok((user_data, role_data));
}

/// Load all users from storage.
pub fn load_all_users() -> Result<Vec<(User, Role)>, std::io::Error> {
    let mut users = vec![];

    for entry in std::fs::read_dir("users")? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(filename) = path.file_name() {
                if let Some(username) = filename.to_str().and_then(|s| s.strip_prefix(".user-")) {
                    if let Ok((user, role)) = load_user(&username.to_string()) {
                        users.push((user, role));
                    }
                }
            }
        }
    }

    Ok(users)
}

/// Save user data to storage with restricted file permissions (0o700).
pub fn save_user(user: &User, create: bool) -> Result<(), std::io::Error> {
    fs::create_dir_all("users").unwrap();

    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions("users", perms.clone()).unwrap();

    let path = format!("{}{}", USER_FILE_PATH, user.id);

    let mut file = OpenOptions::new()
        .create(create)
        .write(true)
        .open(path.clone())?;

    fs::set_permissions(path, perms).unwrap();

    let buf = serde_json::to_vec(user)?;

    let _ = file.write(&buf)?;

    Ok(())
}

/// Save user role data to storage with restricted file permissions (0o700).
pub fn save_role(user: &User, role: &Role, create: bool) -> Result<(), std::io::Error> {
    fs::create_dir_all("roles").unwrap();

    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions("roles", perms.clone()).unwrap();

    let path = format!("{}{}", ROLE_FILE_PATH, user.id);

    let mut file = OpenOptions::new()
        .create(create)
        .write(true)
        .open(path.clone())?;

    fs::set_permissions(path, perms).unwrap();

    let buf = serde_json::to_vec(role)?;

    let _ = file.write(&buf)?;

    Ok(())
}

/// Delete a user and their role data from storage.
pub fn delete_user(user: &str) {
    let _ = fs::remove_file(format!("{}{}", USER_FILE_PATH, user));
    let _ = fs::remove_file(format!("{}{}", ROLE_FILE_PATH, user));
}

/// Interactive user setup wizard (used during server initialization).
pub async fn user_setup(role: RoleType, name: String) -> Result<(User, Role), std::io::Error> {
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    let mut role = Role {
        os_user: String::new(),
        role: role,
    };

    let mut user = User {
        id: name,
        password_hash: String::new(),
        public_cert: vec![],
    };

    println!("\nUser setup: {}", user.id);

    println!("");

    loop {
        println!("Password: ");

        match stdin.next_line().await {
            Ok(Some(l)) => {
                user.password_hash = match hash_password(&l.trim().to_string()) {
                    Ok(hash) => hash,
                    Err(_) => continue,
                };
                break;
            }
            _ => continue,
        };
    }

    println!("");

    println!("System users list:");

    let content = fs::read_to_string("/etc/passwd").expect("Unable to list users.");
    let mut users = vec![];

    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();

        if parts.len() >= 7 {
            let username = parts[0];
            let uid = parts[2];

            println!("{}: {}", uid, username);

            users.push(username.to_string());
        }
    }

    println!("");
    println!("Choose a user: ");

    loop {
        match stdin.next_line().await {
            Ok(Some(l)) => {
                let l = l.trim().to_string();

                if users.contains(&l) {
                    role.os_user = l;
                    break;
                } else {
                    println!("Invalid user. Please enter a valid system user:");
                }
            }
            _ => continue,
        };
    }

    save_user(&user, true)?;
    save_role(&user, &role, true)?;

    Ok((user, role))
}

/// Get the list of available system (os) users from /etc/passwd.
pub fn get_system_user_list() -> Result<Vec<(u16, String)>, std::io::Error> {
    let content = fs::read_to_string("/etc/passwd")?;
    let mut users: Vec<(u16, String)> = vec![];

    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();

        if parts.len() >= 7 {
            let username = parts[0];
            let uid = parts[2];

            users.push((uid.parse::<u16>().unwrap_or(0), username.to_string()));
        }
    }
    Ok(users)
}

/// Handle user panel commands (password change, public key upload).
pub fn handle_user_command(cmd: &UserCommand, cli: &mut Client) -> RequestHandlingResult {
    if cli.auth_status != AuthStatus::Authentified {
        return RequestHandlingResult::None;
    }

    match cmd {
        UserCommand::ChangePassword { new_password } => {
            RequestHandlingResult::Response(Response::UserPanel {
                result: change_user_password(cli, new_password),
            })
        }
        UserCommand::UploadPublicKey { public_key } => {
            RequestHandlingResult::Response(Response::UserPanel {
                result: upload_public_key(cli, public_key),
            })
        }
    }
}

/// Change the authenticated user's password.
pub fn change_user_password(cli: &mut Client, new_password: &str) -> UserCommandResult {
    if cli.user_data.is_none() {
        return UserCommandResult::ChangePassword { success: false };
    }

    if new_password.is_empty() {
        return UserCommandResult::ChangePassword { success: false };
    }

    let hash = match hash_password(new_password) {
        Ok(hash) => hash,
        Err(_) => return UserCommandResult::ChangePassword { success: false },
    };

    let user_data = cli.user_data.as_mut().unwrap();

    user_data.password_hash = hash;

    match save_user(user_data, false) {
        Ok(_) => UserCommandResult::ChangePassword { success: true },
        Err(_) => UserCommandResult::ChangePassword { success: false },
    }
}

/// Upload a new public key for the authenticated user (for certificate authentication).
pub fn upload_public_key(cli: &mut Client, public_key: &Vec<u8>) -> UserCommandResult {
    if cli.user_data.is_none() {
        return UserCommandResult::UploadPublicKey { success: false };
    }

    let user_data = cli.user_data.as_mut().unwrap();

    user_data.public_cert = public_key.clone();

    match save_user(user_data, false) {
        Ok(_) => UserCommandResult::UploadPublicKey { success: true },
        Err(_) => UserCommandResult::UploadPublicKey { success: false },
    }
}
