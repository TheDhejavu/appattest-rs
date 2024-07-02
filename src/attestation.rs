use std::{io::Cursor, time::Duration};
use base64::{engine::general_purpose, Engine};
use ciborium::from_reader;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use crate::{authenticator::AuthenticatorData, error::AppAttestError};
use openssl::{bn::BigNumContext, ec::PointConversionForm, hash::{hash, MessageDigest}, sha::Sha256, stack::Stack, x509::{store::X509StoreBuilder, X509StoreContext, X509}};
use std::error::Error;

use x509_parser::prelude::*;
use der_parser::{ber::BerObjectContent, oid::Oid, parse_ber};


#[derive(Serialize, Deserialize, Debug)]
pub struct Attestation {
    #[serde(rename = "attStmt")]
    statement: Statement,
    #[serde(rename="authData")]
    auth_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Statement {
    #[serde(rename = "x5c")]
    certificates: Vec<Vec<u8>>,
    #[serde(rename = "receipt")]
    receipt: Vec<u8>,
}

impl Attestation {
    /// Creates a new `Attestation` from a Base64-encoded CBOR string.
    /// 
    /// # Arguments
    /// * `base64_attestation` - A string slice containing the Base64-encoded CBOR data.
    ///
    /// # Errors
    /// Returns `AppAttestError` if decoding or deserialization fails.
    pub fn from_base64(base64_attestation: &str) -> Result<Self, AppAttestError> {
        let decoded_bytes = general_purpose::STANDARD
        .decode(base64_attestation)
        .map_err(|e| AppAttestError::Message(format!("Failed to decode Base64: {}", e)))?;

        let cursor = Cursor::new(decoded_bytes);
        let assertion_result: Result<Attestation, _> = from_reader(cursor);  
        if let Ok(assertion) = assertion_result {
            return  Ok(assertion)
        }
        Err(AppAttestError::Message("unable to parse base64 attestation".to_string()))
    }

   /// Fetches the Apple root certificate from the specified URL.
    fn fetch_apple_root_cert(url: &str) -> Result<X509, AppAttestError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppAttestError::Message(format!("Failed to build HTTP client: {}", e)))?;

        let response = client.get(url)
            .send()
            .map_err(|e| AppAttestError::Message(format!("Network request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppAttestError::Message(format!("Failed to fetch: HTTP Status: {}", response.status())));
        }

        let cert_data = response.text()
            .map_err(|e| AppAttestError::Message(format!("Failed to read response text: {}", e)))?;

        let cert = X509::from_pem(cert_data.as_bytes())
            .map_err(|e| AppAttestError::Message(format!("Failed to parse certificate: {}", e)))?;

        Ok(cert)
    }

    /// verifyCertificates verifies the certificate chain in the attestation statement
    fn verify_certificates(certificates: Vec<Vec<u8>>, apple_root_cert: &X509) -> Result<(), Box<dyn Error>> {
        if certificates.is_empty() {
            return Err("certificates is empty".into());
        }
        let mut certs: Vec<X509> = Vec::new();
        for cert_der in certificates {
            let cert: X509 = X509::from_der(&cert_der)?;
            certs.push(cert);
        }
    
        let mut store_builder = X509StoreBuilder::new()?;
        
        store_builder.add_cert(apple_root_cert.clone())?;
    
        let store = store_builder.build();
    
        let mut cert_chain = Stack::new()?;
        for cert in certs.iter().skip(1) {
            cert_chain.push(cert.to_owned())?;
        }
    
        let mut context = X509StoreContext::new()?;
        context.init(&store, &certs[0], &cert_chain, |ctx| {
            ctx.verify_cert()?;
            Ok(())
        })?;

        Ok(())
    }
    // extract_nonce_from_cert extracts the nonce from the certificate
    fn extract_nonce_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, AppAttestError> {
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|_| AppAttestError::Message("Failed to parse certificate".to_string()))?;
    
        let cred_cert_oid = Oid::from(&[1, 2, 840, 113635, 100, 8, 2])
            .map_err(|_| AppAttestError::Message("Failed to parse OID".to_string()))?;
    
        let extensions: &[X509Extension] = cert.extensions();
        let extension_value = extensions.iter()
            .find(|ext| ext.oid == cred_cert_oid)
            .ok_or(AppAttestError::Message("Certificate did not contain credCert extension".to_string()))?
            .value;
    
        let (_, raw_value) = parse_ber(extension_value)
            .map_err(|_| AppAttestError::ExpectedASN1Node)?;
    
        if let BerObjectContent::Sequence(seq) = &raw_value.content {
            for obj in seq {
                match &obj.content {
                    BerObjectContent::Unknown(unknown_obj) => {
                        // Ref: https://cs.opensource.google/go/go/+/refs/tags/go1.22.4:src/encoding/asn1/asn1.go;l=530
                        let offset: usize = 2; 
                        return Ok(unknown_obj.data[offset..].to_vec());
                    },
                    _ => continue, 
                }
            }
            Err(AppAttestError::FailedToExtractValueFromASN1Node)
        } else {
            Err(AppAttestError::ExpectedASN1Node)
        }
    }
  
    // client_data_hash creates SHA256 hash of the challenge
    fn client_data_hash(challenge: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.finish().as_slice().to_vec()
    }

    // nonce_hash creates a new SHA256 hash of the composite item
    fn nonce_hash(auth_data: &Vec<u8>, client_data_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(auth_data);
        
        hasher.update(&client_data_hash);
        hasher.finish().to_vec()
    }

    fn verify_public_key_hash(cert: &X509, key_identifier: &Vec<u8>) -> Result<(Vec<u8>, bool), Box<dyn Error>> {
        let public_key = cert.public_key()?;
        let ecdsa_key = public_key.ec_key()?;
        let ec_point = ecdsa_key.public_key();
        let group = ecdsa_key.group();
    
        // Convert the EC point (public key) into a byte array format
        let mut ctx = BigNumContext::new()?;
        let pub_key_bytes = ec_point.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    
       
        let pub_key_hash = hash(MessageDigest::sha256(), &pub_key_bytes)?;
        Ok((pub_key_bytes, pub_key_hash.as_ref() == key_identifier.as_slice()))
    }
    /// Verify performs the complete attestation verification
    ///
    /// # Arguments
    /// * `challenge` - A reference to the challenge string provided by the verifier.
    /// * `app_id` - A reference to the application identifier.
    /// * `key_id` - A reference to the key identifier expected to match the public key.
    ///
    /// # Returns
    /// This method returns `Ok(())` if all verification steps are successful. If any step fails,
    /// it returns `Err` with an appropriate error encapsulated in a `Box<dyn Error>`.
    ///
    /// # Example
    /// ```no_run
    /// use appattest_rs::attestation::Attestation;
    /// 
    /// let challenge = "example_challenge";
    /// let app_id = "com.example.app";
    /// let key_id = "base64encodedkeyid==";
    ///
    /// let base64_cbor_data = "o2NmbXR....";
    /// let attestation = Attestation::from_base64(base64_cbor_data).expect("unable to convert from base64");
    ///
    /// attestation.verify(challenge, app_id, key_id);
    /// ```
    #[allow(unused_variables)]
    pub fn verify(self, challenge: &str, app_id: &str, key_id: &str) -> Result<(Vec<u8>, Vec<u8>),  Box<dyn Error>> {
        // Step 1: Verify Certificates
        let apple_root_cert = Attestation::fetch_apple_root_cert("https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem")?;
        
        Attestation::verify_certificates(self.statement.certificates.clone(), &apple_root_cert)?;
        
        // Step 2: Parse Authenticator Data
        let auth_data = AuthenticatorData::new(self.auth_data)?;

        // Step 3: Create and Verify Nonce
        let client_data_hash = Attestation::client_data_hash(challenge);
        let nonce = Attestation::nonce_hash(&auth_data.bytes, client_data_hash);

        let cred_cert = X509::from_der(&self.statement.certificates[0])?;

        let key_id_decoded_bytes = general_purpose::STANDARD
        .decode(key_id)  .map_err(|e| AppAttestError::Message(e.to_string()))?;

        // Step 4: Verify Public Key Hash
        let public_key_bytes = Attestation::verify_public_key_hash(&cred_cert, &key_id_decoded_bytes)?;
        if !public_key_bytes.1 {
            return Err(AppAttestError::InvalidPublicKey.into());
        }

        let extracted_nonce= Attestation::extract_nonce_from_cert(&self.statement.certificates[0])?;
        if extracted_nonce.as_slice() != nonce.as_slice() {
            return Err(AppAttestError::InvalidNonce.into());
        }

        // Step 5: Verify App ID Hash
        auth_data.verify_app_id(&app_id)?;

        // Step 6: Verify Counter
        auth_data.verify_counter()?;

        // Step 7: Verify AAGUID
        if !auth_data.is_valid_aaguid() {
            return Err(AppAttestError::InvalidAAGUID.into())
        }

        // Step 8: Verify Credential ID
        auth_data.verify_key_id(&key_id_decoded_bytes)?;

        Ok((public_key_bytes.0.clone(), self.statement.receipt))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
   
    #[test]
    fn test_from_base64_valid() {
        let valid_cbor_base64 = "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";
        let result = Attestation::from_base64(valid_cbor_base64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_certificates_empty() {
        let empty_certs = Vec::new();
        let root_cert_pem = b"-----BEGIN CERTIFICATE-----\n\
        MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n\
        JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n\
        QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n\
        Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n\
        biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n\
        bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n\
        NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n\
        Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n\
        MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n\
        CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n\
        53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n\
        oyFraWVIyd/dganmrduC1bmTBGwD\n\
        -----END CERTIFICATE-----";
        
        let root_cert = openssl::x509::X509::from_pem(root_cert_pem).unwrap();     
        let result = Attestation::verify_certificates(empty_certs, &root_cert);
        assert!(result.is_err());
    }
}