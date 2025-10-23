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
pub enum DnsError {
    #[error("Failed to parse DNS message: {0}")]
    ParsingError(#[from] ParseError),

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
