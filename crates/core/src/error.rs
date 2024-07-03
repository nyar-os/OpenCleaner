use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Message(String),
    /// A capability that exists in the domain model but is not available on
    /// the current platform or build.
    #[error("{capability} is not supported on {platform}")]
    Unsupported { capability: &'static str, platform: &'static str },
}

pub type Result<T> = std::result::Result<T, Error>;
