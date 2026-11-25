pub mod agent_docs;
pub mod config;
pub mod core_adapter;
pub mod error;
pub mod models;
pub mod paths;
pub mod platform;
pub mod preaccel;
pub mod probe;
pub mod process_guard;
pub mod sanitize;
pub mod share_bundle;
pub mod storage;
pub mod strategy;
pub mod subscription;
pub mod sync;
pub mod updater;

pub use error::{CatError, CatResult};
pub use models::RouteTargetMode;
pub use paths::AppPaths;

/// Install the process-wide Rustls ring CryptoProvider (idempotent).
/// Must be called once at process startup before any reqwest HTTPS traffic.
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
