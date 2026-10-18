use crate::server::{Server, TftpOpenError};

use anyhow::{Context, Result};
use async_tftp::packet::Error as TftpError;
use async_tftp::server::{Handler, TftpServerBuilder};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tokio_util::io::StreamReader;

/// The body of one tftp transfer: an async read side fed from a tokio task.
type BodyReader =
    Compat<StreamReader<futures_util::stream::BoxStream<'static, io::Result<Bytes>>, Bytes>>;

/// How many transfers may be open at once. Each one holds a UDP socket, an
/// open file and an internal HTTP response, so an unauthenticated flood must
/// not be allowed to exhaust the process.
const MAX_ACTIVE_TRANSFERS: usize = 64;

/// How long a tftp request may wait for the backend to produce a response
/// before the client gets an error. Local file reads are fast; this catches a
/// stuck disk or an internal dispatch bug.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

struct TftpHandler {
    server: Arc<Server>,
    runtime: tokio::runtime::Handle,
    permits: Arc<Semaphore>,
}

impl TftpHandler {
    fn new(server: Arc<Server>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            server,
            runtime,
            permits: Arc::new(Semaphore::new(MAX_ACTIVE_TRANSFERS)),
        }
    }
}

impl Handler for TftpHandler {
    type Reader = BodyReader;
    type Writer = Compat<tokio::io::Sink>;

    fn read_req_open(
        &mut self,
        client: &SocketAddr,
        path: &Path,
    ) -> impl Future<Output = Result<(Self::Reader, Option<u64>), TftpError>> + Send {
        let server = self.server.clone();
        let runtime = self.runtime.clone();
        let permits = self.permits.clone();
        let client = *client;
        let name = path.to_str().map(|v| v.to_string());
        async move {
            let name = name.ok_or(TftpError::IllegalOperation)?;
            let permit = permits
                .try_acquire_owned()
                .map_err(|_| TftpError::Msg("Server busy, try again later".to_string()))?;
            let (meta_tx, meta_rx) = oneshot::channel();
            let (data_tx, data_rx) = mpsc::channel::<io::Result<Bytes>>(8);

            // The tftp server has its own async-io executor. Do all tokio
            // work (server dispatch, file io) on the main runtime and hand the
            // bytes back through a runtime-independent channel.
            runtime.spawn(async move {
                let _permit = permit;
                let log_name = log_filename(&name);
                match server.tftp_open(&name, client).await {
                    Ok((res, size)) => {
                        info!(
                            "TFTP {client} \"GET {log_name}\" {} {}",
                            res.status().as_u16(),
                            size.map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string())
                        );
                        if meta_tx.send(Ok(size)).is_err() {
                            return;
                        }
                        let mut body = res.into_body().into_data_stream();
                        while let Some(chunk) = body.next().await {
                            let chunk = chunk.map_err(|err| io::Error::other(err.to_string()));
                            if data_tx.send(chunk).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        warn!(
                            "TFTP {client} \"GET {log_name}\" {}",
                            open_error_label(&err)
                        );
                        let _ = meta_tx.send(Err(map_open_error(err)));
                    }
                }
            });

            let size = match tokio::time::timeout(OPEN_TIMEOUT, meta_rx).await {
                Ok(Ok(result)) => result?,
                Ok(Err(_)) => return Err(TftpError::UnknownError),
                Err(_) => return Err(TftpError::Msg("Backend timeout".to_string())),
            };

            let stream = async_stream::stream! {
                let mut rx = data_rx;
                while let Some(item) = rx.recv().await {
                    yield item;
                }
            };
            Ok((StreamReader::new(stream.boxed()).compat(), size))
        }
    }

    async fn write_req_open(
        &mut self,
        _client: &SocketAddr,
        _path: &Path,
        _size: Option<u64>,
    ) -> Result<Self::Writer, TftpError> {
        Err(TftpError::PermissionDenied)
    }
}

/// Escape control characters so a filename cannot forge log lines.
fn log_filename(name: &str) -> String {
    name.chars().flat_map(char::escape_default).collect()
}

fn open_error_label(err: &TftpOpenError) -> &'static str {
    match err {
        TftpOpenError::NotFound => "not found",
        TftpOpenError::Forbidden => "forbidden",
        TftpOpenError::Illegal => "illegal",
        TftpOpenError::Internal(_) => "internal error",
    }
}

fn map_open_error(err: TftpOpenError) -> TftpError {
    match err {
        TftpOpenError::NotFound => TftpError::FileNotFound,
        TftpOpenError::Forbidden => TftpError::PermissionDenied,
        TftpOpenError::Illegal => TftpError::IllegalOperation,
        TftpOpenError::Internal(err) => {
            error!("TFTP backend failed, {err}");
            TftpError::UnknownError
        }
    }
}

/// Start one tftp server per bind address. Tftp itself is read only; all
/// requests are turned into synthetic GET requests by the handler.
pub async fn serve(
    server: Arc<Server>,
    port: u16,
    addrs: &[IpAddr],
    block_size: u16,
    timeout_secs: u64,
) -> Result<Vec<JoinHandle<()>>> {
    let runtime = tokio::runtime::Handle::current();
    let mut handles = vec![];
    for ip in addrs {
        let addr = SocketAddr::new(*ip, port);
        let socket =
            create_udp_socket(addr).with_context(|| format!("Failed to bind tftp '{addr}'"))?;
        let tftp =
            TftpServerBuilder::with_handler(TftpHandler::new(server.clone(), runtime.clone()))
                .std_socket(socket)?
                .timeout(Duration::from_secs(timeout_secs))
                .block_size_limit(block_size)
                .max_send_retries(10)
                .window_size_limit(16)
                .build()
                .await?;
        let listen = tftp.listen_addr()?;
        info!("TFTP listening on {listen}");
        handles.push(tokio::spawn(async move {
            if let Err(err) = tftp.serve().await {
                error!("TFTP server failed, {err}");
            }
        }));
    }
    Ok(handles)
}

fn create_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}
