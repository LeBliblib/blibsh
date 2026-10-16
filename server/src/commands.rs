use common::message::Request;
use tokio::io::AsyncWriteExt;

use crate::{authentication::AuthStatus, client::Client, request_handling::RequestHandlingResult};

/// Handle shell command execution requests.
///
/// Writes the command to the shell's stdin only if the client is authenticated
/// and the shell process has been started.
pub async fn handle_command(req: &Request, cli: &mut Client) -> RequestHandlingResult {
    if let Request::Command { cmd_line } = req {
        if cli.auth_status != AuthStatus::Authentified {
            return RequestHandlingResult::None;
        }

        if !cli.stdin.is_some() {
            return RequestHandlingResult::None;
        }

        let stdin = cli.stdin.as_mut().unwrap();

        let cmd = cmd_line.clone();

        let _ = stdin.write_all(cmd.as_bytes()).await;
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.flush().await;
    }

    return RequestHandlingResult::None;
}
