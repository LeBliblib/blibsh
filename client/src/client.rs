use crate::authentication::AuthStatus;

/// Represents the client session state on the client side.
pub struct Client {
    pub auth_status: AuthStatus,
}
