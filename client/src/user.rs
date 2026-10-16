use common::user::UserCommandResult;

use crate::{CLIENT_CERT, SharedInput, next_input_line, response_handling::ResponseHandlingResult};
use std::io;

/// Handle results from user panel commands executed on the server.
pub fn handle_user_panel_result(cmd_result: &UserCommandResult) -> ResponseHandlingResult {
    match cmd_result {
        UserCommandResult::ChangePassword { success } => {
            if *success {
                println!("Password changed successfully.");
            } else {
                println!("Failed to change password.");
            }
        }
        UserCommandResult::UploadPublicKey { success } => {
            if *success {
                println!("Public key uploaded successfully.");
            } else {
                println!("Failed to upload public key.");
            }
        }
    }

    ResponseHandlingResult::None
}

/// Display password change form and collect new password.
pub async fn change_password_form(lines: &SharedInput) -> Result<String, ()> {
    println!("Enter new password:");

    let password = match next_input_line(lines).await {
        Ok(Some(l)) => l.trim().to_string(),
        _ => return Err(()),
    };

    println!("Confirm new password:");

    let confirm_password = match next_input_line(lines).await {
        Ok(Some(l)) => l.trim().to_string(),
        _ => return Err(()),
    };

    if password != confirm_password {
        println!("Passwords do not match.");
        return Err(());
    }

    Ok(password)
}

/// Load public certificate as a byte vector.
pub fn load_certificate() -> Result<Vec<u8>, io::Error> {
    Ok(CLIENT_CERT.to_vec())
}
