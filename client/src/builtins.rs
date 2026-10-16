use common::{admin::AdminCommand, message::Request, user::UserCommand};

use crate::{
    SharedInput,
    user::{change_password_form, load_certificate},
};

/// Result of processing a built-in command.
pub enum BuiltinResult {
    /// A request should be sent to the server
    Request(Request),
    /// Command processed locally, no request needed
    None,
    /// Not a built-in command
    NotBuiltin,
}

pub async fn handle_builtin(line: &String, lines: &SharedInput) -> BuiltinResult {
    if !line.starts_with('!') {
        return BuiltinResult::NotBuiltin;
    }

    let cmd_line: Vec<&str> = line.split(' ').collect();

    match cmd_line.get(0).unwrap().as_ref() {
        "!exit" => {
            return BuiltinResult::Request(Request::Disconnect {
                reason: String::from("Exit"),
            });
        }
        "!admin" => {
            return BuiltinResult::Request(Request::AdminPanel {
                cmd: AdminCommand::Open,
            });
        }
        "!list_users" => {
            return BuiltinResult::Request(Request::AdminPanel {
                cmd: AdminCommand::ListUsers,
            });
        }
        "!add_user" => {
            let username = cmd_line.get(1);

            if username.is_none() {
                println!("Usage: !add_user <username>");
                return BuiltinResult::None;
            }

            let username = username.unwrap().to_string();

            return BuiltinResult::Request(Request::AdminPanel {
                cmd: AdminCommand::GetAddUserForm { username: username },
            });
        }
        "!remove_user" => {
            let username = cmd_line.get(1);

            if username.is_none() {
                println!("Usage: !remove_user <username>");
                return BuiltinResult::None;
            }

            let username = username.unwrap().to_string();

            return BuiltinResult::Request(Request::AdminPanel {
                cmd: AdminCommand::RemoveUser { username },
            });
        }
        "!user" => {
            println!("\nUser panel:");
            println!("!change_password - Change your password");
            println!("!upload_publickey - Upload a new public key");
            return BuiltinResult::None;
        }
        "!change_password" => {
            let password = match change_password_form(lines).await {
                Ok(p) => p,
                Err(()) => return BuiltinResult::None,
            };

            return BuiltinResult::Request(Request::UserPanel {
                cmd: UserCommand::ChangePassword {
                    new_password: password,
                },
            });
        }
        "!upload_publickey" => {
            let public_key = match load_certificate() {
                Ok(pk) => pk,
                Err(e) => {
                    eprintln!("Failed to load certificate: {}", e);
                    return BuiltinResult::None;
                }
            };

            return BuiltinResult::Request(Request::UserPanel {
                cmd: UserCommand::UploadPublicKey {
                    public_key: public_key,
                },
            });
        }

        _ => return BuiltinResult::NotBuiltin,
    };
}
