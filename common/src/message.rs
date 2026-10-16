use crate::{
    admin::{AdminCommand, AdminCommandResult},
    user::{UserCommand, UserCommandResult},
};

/// Authentication mode enum that specifies how a user wants to authenticate.
///
/// Two modes are supported:
/// - Password: User provides a plaintext password (transmitted over TLS)
/// - Certificate: User uses certificate-based authentication with signature verification
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum AuthMode {
    /// Password-based authentication with plaintext password
    Password { password: Vec<u8> },
    /// Certificate-based authentication with signature verification
    Certificate,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum Request {
    /// Initial authentication request with username and authentication mode
    Auth { user: String, mode: AuthMode },
    /// Response to authentication challenge with signed nonce
    AuthChallenge { sign: Vec<u8> },
    /// Shell command execution request
    Command { cmd_line: String },

    /// User panel command (password change, key upload, etc.)
    UserPanel { cmd: UserCommand },
    /// Admin panel command (user management operations)
    AdminPanel { cmd: AdminCommand },

    /// Client initiated disconnect
    Disconnect { reason: String },
    /// Acknowledgment of server disconnect
    DisconnectAck,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum Response {
    /// Authentication challenge with nonce for signature-based authentication
    AuthChallenge { nonce: Vec<u8> },
    /// Successful authentication
    AuthSuccess,
    /// Shell command standard output
    ShellOut { out: String },
    /// Shell command standard error
    ShellErr { err: String },

    /// User panel command result
    UserPanel { result: UserCommandResult },
    /// Admin panel command result
    AdminPanel { result: AdminCommandResult },

    /// Server initiated disconnect
    Disconnect { reason: String },
    /// Acknowledgment of client disconnect
    DisconnectAck,
}

/// Trait for creating error messages from message types.
///
/// This allows the receiver to create appropriate error messages when communication fails.
pub trait Message<T> {
    /// Create an error message with the given reason
    fn error(reason: String) -> T;
}

impl Message<Response> for Response {
    /// Create a disconnect response as an error
    fn error(reason: String) -> Response {
        Response::Disconnect { reason }
    }
}

impl Message<Request> for Request {
    /// Create a disconnect request as an error
    fn error(reason: String) -> Request {
        Request::Disconnect { reason }
    }
}
