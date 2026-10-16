use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub enum UserCommand {
    /// Change the user's password
    ChangePassword { new_password: String },
    /// Upload a new public key for certificate-based authentication
    UploadPublicKey { public_key: Vec<u8> },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum UserCommandResult {
    ChangePassword { success: bool },
    UploadPublicKey { success: bool },
}
