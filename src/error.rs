use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Header is not large enough")]
    InvalidHeader,

    #[error("Question is not large enough")]
    InvalidQuestion,

    #[error("ResourceRecord is not large enough")]
    InvalidResourcRecord,
}
#[derive(Debug, Error)]
pub enum ResponseCodeError {
    #[error("The name server was unable to interpret the query")]
    FormatError,

    #[error(
        "The name server was unable to process this query due to a problem with the name server"
    )]
    ServerFailure,

    #[error("The domain name referenced in the query does not exist")]
    NameError,

    #[error("The name server does not support the requested kind of query")]
    NotImplemented,

    #[error("The name server refuses to perform the specified operation for policy reasons")]
    Refused,
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("Failed to parse DNS message: {0}")]
    ParsingError(#[from] ParseError),

    #[error("Error in RCODE: {0}")]
    ResponseCodeError(#[from] ResponseCodeError),

    #[error("Network IO failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid format of data")]
    InvalidFormat,

    #[error("Invalid response ID")]
    InvalidResponseID,

    #[error("Max depth reached")]
    MaxDepth,

    #[error("No available servers")]
    NoAvailableServers,

    #[error("Error in delegation")]
    InvalidDelegation,
}
