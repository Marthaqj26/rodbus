use std::net::SocketAddr;

use listener::{Listener, NullListenerServer, ServerState};
use tracing::Instrument;

use crate::decode::DecodeLevel;
use crate::server::task::ServerSetting;
use crate::tcp::server::{ServerTask, TcpServerConnectionHandler};

/// server handling
mod address_filter;
pub(crate) mod handler;
/// Module that contains the features and structures related to listeners.
pub mod listener;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod task;
pub(crate) mod types;

/// Fine for this to be a constant since the corresponding channel is only used to change settings
pub(crate) const SERVER_SETTING_CHANNEL_CAPACITY: usize = 8;

use crate::error::Shutdown;

pub use address_filter::*;
pub use handler::*;

pub use types::*;

// re-export to the public API
#[cfg(feature = "tls")]
pub use crate::tcp::tls::server::TlsServerConfig;
#[cfg(feature = "tls")]
pub use crate::tcp::tls::*;

/// Handle to the server async task. The task is shutdown when the handle is dropped.
#[derive(Debug)]
pub struct ServerHandle {
    tx: tokio::sync::mpsc::Sender<ServerSetting>,
}

impl ServerHandle {
    /// Construct a [ServerHandle] from its fields
    ///
    /// This function is only required for the C bindings
    pub fn new(tx: tokio::sync::mpsc::Sender<ServerSetting>) -> Self {
        ServerHandle { tx }
    }

    /// Change the decoding level for future sessions and all active sessions
    pub async fn set_decode_level(&mut self, level: DecodeLevel) -> Result<(), Shutdown> {
        self.tx.send(ServerSetting::ChangeDecoding(level)).await?;
        Ok(())
    }
}

/// Spawns a TCP server task onto the runtime. This method can only
/// be called from within the runtime context. Use `Runtime::enter()`
/// to create a context on the current thread if necessary.
///
/// Each incoming connection will spawn a new task to handle it.
///
/// * `max_sessions` - Maximum number of concurrent sessions
/// * `addr` - A socket address to bound to
/// * `handlers` - A map of handlers keyed by a unit id
/// * `decode` - Decode log level
///
/// `WARNING`: This function must be called from with the context of the Tokio runtime or it will panic.
pub async fn spawn_tcp_server_task<T: RequestHandler>(
    max_sessions: usize,
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    filter: AddressFilter,
    decode: DecodeLevel,
    event_listener: Option<Box<dyn Listener<ServerState>>>,
) -> Result<ServerHandle, std::io::Error> {
    let tcp_listener = tokio::net::TcpListener::bind(addr).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);

    let task = async move {
        ServerTask::new(
            max_sessions,
            tcp_listener,
            handlers,
            TcpServerConnectionHandler::Tcp,
            filter,
            decode,
            Some(event_listener.unwrap_or_else(|| NullListenerServer::create())),
        )
        .run(rx)
        .instrument(tracing::info_span!("Modbus-Server-TCP", "listen" = ?addr))
        .await;
    };

    tokio::spawn(task);

    Ok(ServerHandle::new(tx))
}

/// Spawns a RTU server task onto the runtime.
///
/// * `path` - Path to the serial device. Generally `/dev/tty0` on Linux and `COM1` on Windows.
/// * `settings` - Serial port settings
/// * `retry` - A boxed trait object that controls when opening the serial port is retried after a failure
/// * `handlers` - A map of handlers keyed by a unit id
/// * `decode` - Decode log level
///
/// `WARNING`: This function must be called from with the context of the Tokio runtime or it will panic.
#[cfg(feature = "serial")]
pub fn spawn_rtu_server_task<T: RequestHandler>(
    path: &str,
    settings: crate::serial::SerialSettings,
    retry: Box<dyn crate::retry::RetryStrategy>,
    handlers: ServerHandlerMap<T>,
    decode: DecodeLevel,
    event_listener: Option<Box<dyn Listener<ServerState>>>,
) -> Result<ServerHandle, std::io::Error> {
    let (tx, rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);
    let event_listener = event_listener.unwrap_or_else(|| NullListenerServer::create());

    let session = crate::server::task::SessionTask::new_with_event_listener(
        handlers,
        crate::server::task::AuthorizationType::None,
        crate::common::frame::FrameWriter::rtu(),
        crate::common::frame::FramedReader::rtu_request(),
        rx,
        decode,
        Some(event_listener),
    );

    let mut rtu = crate::serial::server::RtuServerTask {
        port: path.to_string(),
        retry,
        settings,
        session,
    };

    let path = path.to_string();

    let task = async move {
        rtu.run()
            .instrument(tracing::info_span!("Modbus-Server-RTU", "port" = ?path))
            .await
    };

    tokio::spawn(task);

    Ok(ServerHandle::new(tx))
}

/// Spawns a "raw" TLS server task onto the runtime. This TLS server does NOT require that
/// the client certificate contain the Role extension and allows all operations for any authenticated
/// client.
///
/// Each incoming connection will spawn a new task to handle it.
///
/// * `max_sessions` - Maximum number of concurrent sessions
/// * `addr` - A socket address to bound to
/// * `handlers` - A map of handlers keyed by a unit id
/// * `filter` - Address filter which may be used to restrict the connecting IP address
/// * `tls_config` - TLS configuration
/// * `decode` - Decode log level
///
/// `WARNING`: This function must be called from with the context of the Tokio runtime or it will panic.
#[cfg(feature = "tls")]
pub async fn spawn_tls_server_task<T: RequestHandler>(
    max_sessions: usize,
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    tls_config: TlsServerConfig,
    filter: AddressFilter,
    decode: DecodeLevel,
    event_listener: Option<Box<dyn Listener<ServerState>>>,
) -> Result<ServerHandle, std::io::Error> {
    spawn_tls_server_task_impl(
        max_sessions,
        addr,
        handlers,
        None,
        tls_config,
        filter,
        decode,
        Some(event_listener.unwrap_or_else(|| NullListenerServer::create())),
    )
    .await
}

/// Spawns a "Secure Modbus" TLS server task onto the runtime. This TLS server requires that
/// the client certificate contain the Role extension and checks the authorization of requests against
/// the supplied handler.
///
///
/// Each incoming connection will spawn a new task to handle it.
///
/// * `max_sessions` - Maximum number of concurrent sessions
/// * `addr` - A socket address to bound to
/// * `handlers` - A map of handlers keyed by a unit id
/// * `auth_handler` - Handler used to authorize requests
/// * `tls_config` - TLS configuration
/// * `filter` - Address filter which may be used to restrict the connecting IP address
/// * `decode` - Decode log level
///
/// `WARNING`: This function must be called from with the context of the Tokio runtime or it will panic.
#[cfg(feature = "tls")]
pub async fn spawn_tls_server_task_with_authz<T: RequestHandler>(
    max_sessions: usize,
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    auth_handler: std::sync::Arc<dyn AuthorizationHandler>,
    tls_config: TlsServerConfig,
    filter: AddressFilter,
    decode: DecodeLevel,
    event_listener: Option<Box<dyn Listener<ServerState>>>,
) -> Result<ServerHandle, std::io::Error> {
    spawn_tls_server_task_impl(
        max_sessions,
        addr,
        handlers,
        Some(auth_handler),
        tls_config,
        filter,
        decode,
        Some(event_listener.unwrap_or_else(|| NullListenerServer::create())),
    )
    .await
}

#[cfg(feature = "tls")]
async fn spawn_tls_server_task_impl<T: RequestHandler>(
    max_sessions: usize,
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    auth_handler: Option<std::sync::Arc<dyn AuthorizationHandler>>,
    tls_config: TlsServerConfig,
    filter: AddressFilter,
    decode: DecodeLevel,
    event_listener: Option<Box<dyn Listener<ServerState>>>,
) -> Result<ServerHandle, std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);

    let task = async move {
        ServerTask::new(
            max_sessions,
            listener,
            handlers,
            TcpServerConnectionHandler::Tls(tls_config, auth_handler),
            filter,
            decode,
            Some(event_listener.unwrap_or_else(|| NullListenerServer::create())),
        )
        .run(rx)
        .instrument(tracing::info_span!("Modbus-Server-TLS", "listen" = ?addr))
        .await
    };

    tokio::spawn(task);

    Ok(ServerHandle::new(tx))
}

/// Spawns a Modbus RTU over TCP server.
///
/// This function starts a server that listens for Modbus RTU frames sent over a TCP connection.
/// Each incoming connection is handled asynchronously.
///
/// # Arguments
/// - `addr`: The socket address where the server will listen.
/// - `handlers`: A map of request handlers to process Modbus requests.
/// - `decode`: The decoding level to apply for debugging or verbose logs.
///
/// # Returns
/// - `Result<ServerHandle, std::io::Error>`: The server handle if the operation succeeds,
/// or an I/O error if the server fails to start.
#[cfg(feature = "overtcp")]
pub async fn spawn_rtu_overtcp_server_task<T: RequestHandler>(
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    decode: DecodeLevel,
) -> Result<ServerHandle, std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);

    let mut session = crate::server::task::SessionTask::new(
        handlers,
        crate::server::task::AuthorizationType::None,
        crate::common::frame::FrameWriter::rtu(),
        crate::common::frame::FramedReader::rtu_request(),
        rx,
        decode,
    );
    let task = async move {
        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    tracing::info!("New connection from {:?}", client_addr);
                    println!("[:{}] New connection from {:?}", line!(), client_addr);

                    let mut phys_layer = crate::common::phys::PhysLayer::new_tcp(stream);

                    let result = session.run(&mut phys_layer).await;
                    match result {
                        crate::RequestError::Io(error_kind) => {
                            println!("[:{}] Err! {:?}", line!(), error_kind)
                        }
                        crate::RequestError::Exception(exception_code) => {
                            println!("[{}:{}] Err! {:?}", file!(), line!(), exception_code)
                        }
                        crate::RequestError::BadRequest(invalid_request) => {
                            println!("[{}:{}] Err! {:?}", file!(), line!(), invalid_request)
                        }
                        crate::RequestError::BadFrame(frame_parse_error) => {
                            println!("[{}:{}] Err! {:?}", file!(), line!(), frame_parse_error)
                        }
                        crate::RequestError::BadResponse(adu_parse_error) => {
                            println!("[{}:{}] Err! {:?}", file!(), line!(), adu_parse_error)
                        }
                        crate::RequestError::ResponseTimeout => {
                            println!("[{}:{}] ResponseTimeout", file!(), line!())
                        }
                        crate::RequestError::NoConnection => {
                            println!("[{}:{}] NoConnection", file!(), line!())
                        }
                        crate::RequestError::Internal(internal) => {
                            println!("[{}:{}] Err! {:?}", file!(), line!(), internal)
                        }
                        crate::RequestError::Shutdown => {
                            println!("Session with {:?} terminated due to Shutdown.", client_addr)
                        }
                    }
                }

                Err(e) => {
                    tracing::error!("Error accepting connection: {:?}", e);
                }
            }
        }
    };

    tokio::spawn(task);

    Ok(ServerHandle::new(tx))
}
