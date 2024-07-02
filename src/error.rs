use std::{error::Error, fmt};

#[derive(Debug, PartialEq)]
pub enum AppAttestError {
    InvalidNonce,
    InvalidAppIDHash,
    InvalidPublicKey,
    InvalidCounter,
    InvalidCredentialID,
    InvalidAAGUID,
    InvalidSignature,
    InvalidAppID,
    InvalidClientData,
    ExpectedASN1Node,
    FailedToExtractValueFromASN1Node,
    ExpectedOctetStringInsideASN1Node,
    
    Message(String)
}

impl fmt::Display for AppAttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppAttestError::Message(e) => write!(f, "{}", e),
            AppAttestError::InvalidNonce => write!(f, "invalid nonce"),
            AppAttestError::InvalidAppIDHash => write!(f, "invalid App ID hash"),
            AppAttestError::InvalidPublicKey => write!(f, "invalid public key"),
            AppAttestError::InvalidCounter => write!(f, "invalid counter"),
            AppAttestError::InvalidCredentialID => write!(f, "invalid credential ID"),
            AppAttestError::InvalidAAGUID => write!(f, "invalid AAGUID"),
            AppAttestError::InvalidSignature => write!(f, "invalid signature"),
            AppAttestError::InvalidAppID => write!(f, "invalid App ID"),
            AppAttestError::InvalidClientData => write!(f, "invalid client data"),
            AppAttestError::ExpectedASN1Node => write!(f, "expected ASN1 node"),
            AppAttestError::FailedToExtractValueFromASN1Node => write!(f, "failed to extract value from ASN1 node"),
            AppAttestError::ExpectedOctetStringInsideASN1Node => write!(f, "expected octet string inside ASN1 node"),
        }
    }
}

impl Error for AppAttestError {}