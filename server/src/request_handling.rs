use common::message::{AuthMode, Request, Response};

use crate::{
    admin::handle_admin_command,
    authentication::{handle_auth_challenge, handle_certificate_auth, handle_password_auth},
    client::Client,
    commands::handle_command,
    user::handle_user_command,
};

#[derive(Debug)]
pub enum RequestHandlingResult {
    Response(Response),
    None,
}

/// Handle an incoming request by dispatching to the appropriate handler.
pub async fn handle_request(req: &Request, cli: &mut Client) -> RequestHandlingResult {
    match &req {
        Request::Auth { user: _, mode } => match mode {
            AuthMode::Password { .. } => handle_password_auth(&req, cli).await,
            AuthMode::Certificate => handle_certificate_auth(&req, cli).await,
        },
        Request::AuthChallenge { .. } => handle_auth_challenge(&req, cli).await,
        Request::Command { .. } => handle_command(req, cli).await,
        Request::Disconnect { reason } => {
            println!("Client {} requested disconnect: {}", cli.client_id, reason);
            RequestHandlingResult::Response(Response::DisconnectAck)
        }
        Request::AdminPanel { cmd } => handle_admin_command(cmd, cli),
        Request::UserPanel { cmd } => handle_user_command(cmd, cli),
        Request::DisconnectAck => RequestHandlingResult::None,
    }
}
