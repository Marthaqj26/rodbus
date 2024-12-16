use crate::MaybeAsync;

/// Trait para manejar cambios de estado del servidor
pub trait Listener<T>: Send + Sync {
    /// Inform the listener that the value has changed
    fn update(&mut self, _state: T) -> MaybeAsync<()> {
        MaybeAsync::ready(())
    }
}

/// Listener that does nothing
#[derive(Copy, Clone)]
pub(crate) struct NullListenerServer;

impl NullListenerServer {
    /// Create a Box<dyn Listener<T>> that does nothing
    pub(crate) fn create<T>() -> Box<dyn Listener<T>> {
        Box::new(NullListenerServer)
    }
}

impl<T> Listener<T> for NullListenerServer {
    fn update(&mut self, _value: T) -> MaybeAsync<()> {
        MaybeAsync::ready(())
    }
}
/// State of TCP/TLS server connection
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServerState {
    /// Server is disabled
    Disabled,
    /// Serverattempting to establish a connection
    Connecting,
    /// Serveris connected
    Connected,
    /// Server has been shut down
    Shutdown,
}
