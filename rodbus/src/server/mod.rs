use std::net::SocketAddr;

use tokio_util::bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::Instrument;

use crate::decode::DecodeLevel;
use crate::server::task::ServerSetting;
use crate::tcp::server::{ServerTask, TcpServerConnectionHandler};
use futures_util::sink::SinkExt;
use tokio_stream::StreamExt;

/// server handling
mod address_filter;
pub(crate) mod handler;
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
) -> Result<ServerHandle, std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);

    let task = async move {
        ServerTask::new(
            max_sessions,
            listener,
            handlers,
            TcpServerConnectionHandler::Tcp,
            filter,
            decode,
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
) -> Result<ServerHandle, std::io::Error> {
    let (tx, rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);
    let session = crate::server::task::SessionTask::new(
        handlers,
        crate::server::task::AuthorizationType::None,
        crate::common::frame::FrameWriter::rtu(),
        crate::common::frame::FramedReader::rtu_request(),
        rx,
        decode,
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
) -> Result<ServerHandle, std::io::Error> {
    spawn_tls_server_task_impl(
        max_sessions,
        addr,
        handlers,
        None,
        tls_config,
        filter,
        decode,
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
) -> Result<ServerHandle, std::io::Error> {
    spawn_tls_server_task_impl(
        max_sessions,
        addr,
        handlers,
        Some(auth_handler),
        tls_config,
        filter,
        decode,
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
    _handlers: ServerHandlerMap<T>,
    _decode: DecodeLevel,
) -> Result<ServerHandle, std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Servidor RTU over TCP escuchando en {}", addr);

    let (tx, _rx) = tokio::sync::mpsc::channel(SERVER_SETTING_CHANNEL_CAPACITY);

    let task = async move {
        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    println!("Nueva conection desde {:?}", addr);

                    let mut framed = tokio_util::codec::Framed::new(stream, ModbusRtuOverTcpCodec);

                    tokio::spawn(async move {
                        while let Some(Ok((unit_id, function_code, data))) = framed.next().await {
                            println!(
                                "Unidad {}: Código de Función {}: Datos recibidos: {:?}",
                                unit_id, function_code, data
                            );

                            let response_data = match function_code {
                                0x01 | 0x02 | 0x03 | 0x04 => vec![0x02, 0x00, 0x01], // Ejemplo: Leer registros
                                0x05 | 0x06 => vec![0x00, 0x01], // Ejemplo: Escribir un registro
                                _ => vec![function_code | 0x80, 0x01], // Código de función no soportado
                            };

                            if !response_data.is_empty() {
                                if let Err(e) = framed.send((unit_id, response_data)).await {
                                    match e.kind() {
                                        std::io::ErrorKind::ConnectionReset => {
                                            println!(
                                                "Conexión reiniciada por el cliente: {}",
                                                client_addr
                                            );
                                        }
                                        std::io::ErrorKind::BrokenPipe => {
                                            println!(
                                                "Conexión cerrada inesperadamente: {}",
                                                client_addr
                                            );
                                        }
                                        _ => {
                                            eprintln!(
                                                "Error inesperado al enviar respuesta: {}",
                                                e
                                            );
                                        }
                                    }
                                    break;
                                }
                            }
                        }

                        println!("Conexión cerrada desde {}", client_addr);
                    });
                }

                Err(e) => {
                    tracing::error!("Error al aceptar conection: {:?}", e);
                }
            }
        }
    };

    tokio::spawn(task);

    Ok(ServerHandle::new(tx))
}

const MIN_RTU_FRAME_SIZE: usize = 4; // Mínimo: Unit ID (1) + Function Code (1) + CRC (2)

#[derive(Copy, Clone)]

/// ModbusRtuOverTcpCodec
pub struct ModbusRtuOverTcpCodec;

impl Decoder for ModbusRtuOverTcpCodec {
    type Item = (u8, u8, Vec<u8>); // Unit ID y Datos
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Verificar longitud mínima
        if src.len() < MIN_RTU_FRAME_SIZE {
            return Ok(None); // Esperar más datos
        }

        // Extraer Unit ID, Function Code, y Datos (ignorando el CRC)
        let unit_id = src[0];
        let function_code = src[1];
        let data_end = src.len() - 2; // Excluye el CRC
        let data = src[2..data_end].to_vec();

        // Remover los bytes procesados del buffer
        src.advance(src.len());

        Ok(Some((unit_id, function_code, data)))
    }
}

impl Encoder<(u8, Vec<u8>)> for ModbusRtuOverTcpCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: (u8, Vec<u8>), dst: &mut BytesMut) -> Result<(), Self::Error> {
        let (unit_id, data) = item;

        // Crea la trama RTU
        dst.extend_from_slice(&[unit_id]); //unit ID
        dst.extend_from_slice(&data); //Datos

        // Calcular el CRC
        let crc = calculate_crc(&dst);
        dst.extend_from_slice(&crc.to_le_bytes());

        Ok(())
    }
}

fn calculate_crc(frame: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in frame {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc >>= 1;
                crc ^= 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}
