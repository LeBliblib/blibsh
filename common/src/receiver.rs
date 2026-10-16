use tokio::{
    io::{AsyncReadExt, ReadHalf},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::TlsStream;

use crate::message::Message;

/// Async message receiver that reads from a TLS stream and sends deserialized messages to a channel.
#[derive(Debug)]
pub struct Receiver<T: for<'a> serde::Deserialize<'a>>
where
    T: for<'a> serde::Deserialize<'a> + Message<T>,
{
    stream: ReadHalf<TlsStream<TcpStream>>,
    /// MPSC sender channel for sending deserialized messages
    channel: mpsc::Sender<T>,
}

impl<T> Receiver<T>
where
    T: for<'a> serde::Deserialize<'a> + Message<T>,
{
    /// Create a new Receiver from a TLS stream reader and message channel.
    pub fn new(stream: ReadHalf<TlsStream<TcpStream>>, channel: mpsc::Sender<T>) -> Self {
        Self { stream, channel }
    }

    /// Deserialize a message from bytes using MessagePack format.
    fn deserialize(buf: &mut [u8]) -> Result<T, String> {
        let res = rmp_serde::from_slice::<T>(buf);

        if let Err(e) = res {
            return Err(format!("Unable to deserialize message. {}", e));
        }

        Ok(res.unwrap())
    }

    /// Run the receiver loop, continuously reading and processing messages from the stream.
    ///
    /// This method runs indefinitely until an error occurs or the connection is closed.
    /// Messages are sent through the channel to be processed by the receiver owner.
    pub async fn run(&mut self) -> Result<(), String> {
        loop {
            // Read the message size (8 bytes, little-endian)
            let mut buf = [0u8; size_of::<usize>()];

            let res = self.stream.read_exact(&mut buf).await;

            if let Err(_) = res {
                let _ = self
                    .channel
                    .send(T::error(
                        "Unexpected error while receiving data.".to_string(),
                    ))
                    .await;
                break;
            }

            let size = usize::from_le_bytes(buf);

            // Read the message data
            let mut buf = vec![0u8; size];

            if let Err(_) = self.stream.read_exact(&mut buf).await {
                let _ = self
                    .channel
                    .send(T::error(
                        "Unexpected error while receiving data.".to_string(),
                    ))
                    .await;
                break;
            }

            // Deserialize the message
            let res = Self::deserialize(&mut buf);

            if let Err(_) = res {
                let _ = self
                    .channel
                    .send(T::error(
                        "Unexpected error while receiving data.".to_string(),
                    ))
                    .await;
                break;
            }

            let req: T = res.unwrap();

            // Send the message through the channel
            let res = self.channel.send(req).await;

            if let Err(e) = res {
                println!("Producer error while sending deserialized message. {}", e);
                break;
            }
        }

        Ok(())
    }
}
