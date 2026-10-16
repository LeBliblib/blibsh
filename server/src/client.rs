use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsStream};

use common::{
    message::{Request, Response},
    receiver::Receiver,
};

use crate::{
    authentication::AuthStatus,
    request_handling::handle_request,
    user::{Role, User},
};

use crate::request_handling::RequestHandlingResult;

/// Represents the exit status of a client connection handler loop.
#[derive(PartialEq, Eq)]
enum ExitStatus {
    /// Immediately kill the connection
    Kill,
    /// Wait for disconnect acknowledgment from client
    WaitingForAck,
    /// Successfully exit this phase (continue to next phase)
    Success,
}

/// Represents a connected client session.
pub struct Client {
    /// The client's socket address
    pub client_id: SocketAddr,

    /// Current authentication status of the client
    pub auth_status: AuthStatus,
    /// User information (set after successful authentication)
    pub user_data: Option<User>,
    /// Role information (set after successful authentication)
    pub role_data: Option<Role>,

    /// The spawned shell process
    pub shell_process: Option<tokio::process::Child>,
    /// Standard input stream to the shell
    pub stdin: Option<tokio::process::ChildStdin>,
    /// Standard output stream from the shell
    pub stdout: Option<tokio::process::ChildStdout>,
    /// Standard error stream from the shell
    pub stderr: Option<tokio::process::ChildStderr>,

    /// Handle to the async receiver task
    pub receiver_handle: Option<tokio::task::JoinHandle<Result<(), String>>>,
}

impl Client {
    pub fn new(client_id: SocketAddr) -> Client {
        return Client {
            client_id,
            auth_status: AuthStatus::NotAuthentified,
            user_data: None,
            role_data: None,
            shell_process: None,
            stdin: None,
            stdout: None,
            stderr: None,
            receiver_handle: None,
        };
    }

    pub fn set_user(&mut self, user: User, role: Role) {
        self.user_data = Some(user);
        self.role_data = Some(role);
    }

    pub fn set_auth_status(&mut self, status: AuthStatus) {
        self.auth_status = status;
    }

    pub fn set_shell_process(
        &mut self,
        process: tokio::process::Child,
        stdin: tokio::process::ChildStdin,
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
    ) {
        self.shell_process = Some(process);
        self.stdin = Some(stdin);
        self.stdout = Some(stdout);
        self.stderr = Some(stderr);
    }

    fn cleanup(&mut self) {
        if let Some(handle) = &self.receiver_handle {
            handle.abort();
        }

        if let Some(process) = &mut self.shell_process {
            let _ = process.kill();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Main handler for a single client connection.
///
/// Manages the complete lifecycle of a client session:
/// 1. Performs TLS handshake
/// 2. Runs authentication loop (password or certificate auth)
/// 3. Upon auth success, spawns shell and runs command loop
/// 4. Handles graceful disconnection
pub async fn client_handler(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    peer: SocketAddr,
) -> Result<(), String> {
    // Perform TLS handshake
    let stream = acceptor.accept(stream).await;

    let stream = match stream {
        Ok(s) => s,
        Err(e) => {
            eprintln!("TLS handshake failed with {}: {}", peer, e);
            return Err(format!("TLS handshake failed with {}: {}", peer, e));
        }
    };

    let mut cli = Client::new(peer);
    println!("Client {} connected.", cli.client_id);

    let stream = TlsStream::Server(stream);

    let (stream_reader, mut stream_writer) = tokio::io::split(stream);

    // Create channel for receiving messages from the async receiver task
    let (req_producer, mut req_receiver) = mpsc::channel::<Request>(64);
    let mut receiver = Receiver::new(stream_reader, req_producer);
    cli.receiver_handle = Some(tokio::spawn(async move { receiver.run().await }));

    // Phase 1: Authentication loop
    let exit_status = auth_loop(&mut cli, &mut req_receiver, &mut stream_writer).await;

    match exit_status {
        ExitStatus::Kill => {
            let _ = stream_writer.flush().await;
            let _ = stream_writer.shutdown().await;
            println!("Client {} disconnected.", cli.client_id);
            return Ok(());
        }
        ExitStatus::WaitingForAck => {
            wait_for_disconnect_ack(&mut req_receiver).await;
            println!("Client {} disconnected.", cli.client_id);
            return Ok(());
        }
        ExitStatus::Success => {}
    }

    // Phase 2: Command execution loop (after auth success)
    let exit_status = default_loop(&mut cli, &mut req_receiver, &mut stream_writer).await;

    match exit_status {
        ExitStatus::Kill => {
            let _ = stream_writer.flush().await;
            let _ = stream_writer.shutdown().await;
        }
        ExitStatus::WaitingForAck => {
            wait_for_disconnect_ack(&mut req_receiver).await;
        }
        ExitStatus::Success => {}
    }

    println!("Client {} disconnected.", cli.client_id);
    Ok(())
}

/// Wait for the client to acknowledge the disconnect message.
///
/// Waits up to 3 seconds for a DisconnectAck message from the client.
async fn wait_for_disconnect_ack(req_receiver: &mut mpsc::Receiver<Request>) {
    loop {
        match tokio::time::timeout(Duration::from_secs(3), req_receiver.recv()).await {
            Ok(Some(msg)) => {
                if let Request::DisconnectAck = msg {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                break;
            }
        }
    }
}

/// Authentication phase loop.
///
/// Process requests until an AuthSuccess response is sent, or a disconnect is requested by either side.
async fn auth_loop(
    cli: &mut Client,
    req_receiver: &mut mpsc::Receiver<Request>,
    stream_writer: &mut tokio::io::WriteHalf<TlsStream<TcpStream>>,
) -> ExitStatus {
    loop {
        let req = match req_receiver.recv().await {
            Some(req) => req,
            None => return ExitStatus::Kill,
        };

        let response = handle_request(&req, cli).await;

        let response = match response {
            RequestHandlingResult::Response(r) => r,
            RequestHandlingResult::None => {
                continue;
            }
        };

        let res = send_response(&response, stream_writer).await;

        if let Err(e) = res {
            eprintln!("Failed to send response to {}: {}", cli.client_id, e);
            return ExitStatus::Kill;
        }

        match response {
            Response::AuthSuccess => {
                return ExitStatus::Success;
            }
            Response::Disconnect { reason } => {
                println!("Disconnecting {}: {}...", cli.client_id, reason);
                return ExitStatus::WaitingForAck;
            }
            Response::DisconnectAck => {
                return ExitStatus::Kill;
            }
            _ => {}
        };
    }
}

/// Command execution phase loop.
///
/// After authentication, multiplexes between:
/// - Reading stdout from the shell process
/// - Reading stderr from the shell process
/// - Receiving incoming command requests from the client
async fn default_loop(
    cli: &mut Client,
    req_receiver: &mut mpsc::Receiver<Request>,
    stream_writer: &mut tokio::io::WriteHalf<TlsStream<TcpStream>>,
) -> ExitStatus {
    if cli.shell_process.is_none() || cli.stdin.is_none() || cli.stdout.is_none() {
        let _ = send_response(
            &Response::Disconnect {
                reason: String::from("Shell process failed to started."),
            },
            stream_writer,
        )
        .await;
        return ExitStatus::WaitingForAck;
    }

    let mut out_buf = [0u8; 1024];
    let mut err_buf = [0u8; 1024];

    loop {
        tokio::select! {
            Ok(n) = cli.stdout.as_mut().unwrap().read(&mut out_buf) => {
                let line = String::from_utf8_lossy(&out_buf[..n]).to_string();
                let res = send_response(&Response::ShellOut { out: line }, stream_writer).await;

                if let Err(e) = res {
                    eprintln!("Failed to send stdout to {}: {}", cli.client_id, e);
                    return ExitStatus::Kill;
                }
            }

            Ok(n) = cli.stderr.as_mut().unwrap().read(&mut err_buf ) => {
                let line = String::from_utf8_lossy(&err_buf[..n]).to_string();
                let res = send_response(&Response::ShellErr { err: line }, stream_writer).await;

                if let Err(e) = res {
                    eprintln!("Failed to send stderr to {}: {}", cli.client_id, e);
                    return ExitStatus::Kill;
                }
            }

            Some(req) = req_receiver.recv() => {
                let response = handle_request(&req, cli).await;

                let response = match response {
                    RequestHandlingResult::Response(r) => r,
                    RequestHandlingResult::None => {
                        continue;
                    }
                };

                let res = send_response(&response, stream_writer).await;

                if let Err(e) = res {
                    eprintln!("Failed to send response to {}: {}", cli.client_id, e);
                    return ExitStatus::Kill;
                }

                if let Response::Disconnect { reason } = response {
                    println!("Disconnecting {}: {}...", cli.client_id, reason);
                    return ExitStatus::WaitingForAck;
                }

                if let Response::DisconnectAck = response {
                    return ExitStatus::Kill;
                }
            }
        }
    }
}

/// Send a response message to the client over the TLS stream.
///
/// Serializes the response using MessagePack with a usize size header representing msg length.
/// [8-byte size in little-endian] [serialized message]
async fn send_response(
    response: &Response,
    stream_writer: &mut tokio::io::WriteHalf<TlsStream<TcpStream>>,
) -> Result<(), io::Error> {
    let res = rmp_serde::to_vec(response);

    if let Err(e) = res {
        eprintln!("Unable to serialize response. {}", e);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Unable to serialize response.",
        ));
    }

    let buf = res.unwrap();

    let header = buf.len();
    stream_writer.write(&header.to_le_bytes()).await?;
    stream_writer.write(&buf).await?;

    Ok(())
}
