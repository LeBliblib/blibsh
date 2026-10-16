use common::message::{Request, Response};

use crate::{
    SharedInput,
    admin::handle_admin_panel_result,
    authentication::{handle_auth_challenge, handle_auth_success},
    client::Client,
    user::handle_user_panel_result,
};

pub enum ResponseHandlingResult {
    /// A request should be sent in response
    Request(Request),
    /// No response needed
    None,
}

/// Handle an incoming response from the server.
/// Routes responses to appropriate handlers based on response type.
pub async fn handle_response(
    response: &Response,
    client: &mut Client,
    lines: &SharedInput,
) -> ResponseHandlingResult {
    match &response {
        Response::AuthChallenge { .. } => handle_auth_challenge(&response, client),
        Response::AuthSuccess => handle_auth_success(client),
        Response::ShellOut { out } => {
            println!("{}", out);
            ResponseHandlingResult::None
        }
        Response::ShellErr { err } => {
            eprintln!("{}", err);
            ResponseHandlingResult::None
        }
        Response::Disconnect { reason } => {
            println!("Server requested disconnect: {}", reason);
            return ResponseHandlingResult::Request(Request::DisconnectAck);
        }
        Response::AdminPanel { result } => handle_admin_panel_result(result, lines).await,
        Response::UserPanel { result } => handle_user_panel_result(result),
        Response::DisconnectAck => ResponseHandlingResult::None,
    }
}
