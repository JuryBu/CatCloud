use thiserror::Error;

pub type CatResult<T> = Result<T, CatError>;

#[derive(Debug, Error)]
pub enum CatError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Invalid configuration: {0}")]
    Config(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Security policy blocked operation: {0}")]
    Security(String),
    #[error("Process lifecycle error: {0}")]
    Process(String),
    #[error("Core adapter error: {0}")]
    Core(String),
    #[error("Formula evaluation error: {0}")]
    Formula(String),
    #[error("Not found: {0}")]
    NotFound(String),
}
