use std::{time::Duration};

use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use crate::{authenticator::AuthenticatorData, error::AppAttestError};
use openssl::{bn::BigNumContext, ec::PointConversionForm, hash::{hash, MessageDigest}, sha::Sha256, stack::Stack, x509::{store::X509StoreBuilder, X509Extension, X509StoreContext, X509}};
use std::error::Error;


#[derive(Serialize, Deserialize, Debug)]
struct Attestation {
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
            .decode(base64_attestation)  .map_err(|e| AppAttestError::Message(e.to_string()))?;

        let attestation: Attestation = serde_cbor::from_slice(&decoded_bytes)
            .map_err(|e| AppAttestError::Message(e.to_string()))?;
        
        Ok(attestation)
    }

    /// Fetches the Apple root certificate from the specified URL.
    async fn fetch_apple_root_cert(url: &str) -> Result<X509, AppAttestError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppAttestError::Message(format!("Failed to build HTTP client: {}", e)))?;
    
        let response = client.get(url)
            .send()
            .await
            .map_err(|e| AppAttestError::Message(format!("Network request failed: {}", e)))?;
    
        if !response.status().is_success() {
            return Err(AppAttestError::Message(format!("Failed to fetch: HTTP Status: {}", response.status())));
        }
    
        let cert_data = response.text().await
            .map_err(|e| AppAttestError::Message(format!("Failed to read response text: {}", e)))?;
        

        let cert = X509::from_pem(cert_data.as_bytes())
            .map_err(|e| AppAttestError::Message(format!("Failed to parse cerificate: {}", e)))?;
        
        Ok(cert)
    }

    /// verifyCertificates verifies the certificate chain in the attestation statement
    fn verify_certificates(certificates: Vec<Vec<u8>>, apple_root_cert: &X509) -> Result<(), Box<dyn Error>> {
        let mut store_builder = X509StoreBuilder::new()?;
        let mut intermediates = Stack::new()?;
    
        // Add all intermediate certificates to the stack
        for cert_der in certificates.iter().skip(1) {
            let cert = X509::from_der(cert_der)?;
            intermediates.push(cert)?;
        }
    
        store_builder.add_cert(apple_root_cert.clone())?;
    
        let store = store_builder.build();
        let target_cert = X509::from_der(&certificates[0])?;
    
        let mut store_ctx = X509StoreContext::new()?;
        store_ctx.init(&store, &target_cert, &intermediates, |_ctx| {
            Ok(())
        })?;
    
        // Verify the certificate
        store_ctx.verify_cert()?;
    
        Ok(())
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
    /// ```
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let challenge = "example_challenge";
    ///     let app_id = "com.example.app";
    ///     let key_id = "base64encodedkeyid==";
    ///
    ///     let attestation_data = "base64_encoded_attestation_data"; 
    ///     let attestation = Attestation::from_base64(attestation_data)?;
    ///
    ///     attestation.verify(challenge, app_id, key_id).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn verify(self, challenge: &str, app_id: &str, key_id: &str) -> Result<((Vec<u8>, Vec<u8>)),  Box<dyn Error>> {
        // Step 1: Verify Certificates
        let apple_root_cert = Attestation::fetch_apple_root_cert("https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem").await?;
        
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
        if public_key_bytes.1 {
            return Err(AppAttestError::InvalidPublicKey.into());
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

        Ok((public_key_bytes.0, todo!()))
    }
}
