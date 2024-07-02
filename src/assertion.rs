use base64::{engine::general_purpose, Engine};
use p256::ecdsa::{self, signature::Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use ciborium::de::from_reader;
use std::io::Cursor;
use serde::{Deserialize, Serialize};
use std::error::Error;
use crate::{authenticator::AuthenticatorData, error::AppAttestError};


#[derive(Serialize, Deserialize, Debug)]
pub struct Assertion {
    #[serde(rename = "authenticatorData")]
    raw_authenticator_data: Vec<u8>,
    #[serde(rename = "signature")]
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientData {
    challenge: String,
}

impl Assertion {

    /// Creates a new `Assertion` from a Base64-encoded CBOR string.
    /// 
    /// # Arguments
    /// * `base64_assertion` - A string slice containing the Base64-encoded CBOR data.
    ///
    /// # Errors
    /// Returns `AppAttestError` if decoding or deserialization fails.
    pub fn from_base64(base64_assertion: &str) -> Result<Self, AppAttestError> {
        let decoded_bytes = general_purpose::STANDARD
            .decode(base64_assertion)
            .map_err(|e| AppAttestError::Message(format!("Failed to decode Base64: {}", e)))?;

        let cursor = Cursor::new(decoded_bytes);
        let assertion_result: Result<Assertion, _> = from_reader(cursor);  
        if let Ok(assertion) = assertion_result {
            return  Ok(assertion)
        }
        Err(AppAttestError::Message("unable to parse assertion".to_string()))
    }

    /// Verifies the authenticity of an assertion using provided data and cryptographic checks.
    /// # Arguments
    /// * `client_data_byte` - A vector of bytes representing serialized client data.
    /// * `app_id` - A string slice representing the application identifier.
    /// * `public_key_byte` - A vector of bytes representing the public key used for verifying the signature.
    /// * `previous_counter` - The counter value from the last successful verification.
    /// * `stored_challenge` - A string slice representing the challenge previously issued to the client.
    ///
    /// # Example
    /// ```
    /// use appattest_rs::assertion::Assertion;
    /// use base64::{engine::general_purpose, Engine};
    /// 
    /// let client_data_json = r#"{"challenge": "challenge123"}"#.as_bytes().to_vec();
    /// let app_id = "com.example.app";
    /// let public_key_base64 = "BLROJkpk8NoHVHAnkLOKWUrc4MhyMkATpDyDwjEk82o+uf+KCQiDoHZdlcJ1ff5HPgK7Jd/pTA3cyKOq5MYM6Gs=";
    /// let public_key_bytes = general_purpose::STANDARD.decode(public_key_base64).expect("unable to decode public key");
    /// let previous_counter = 5;
    /// let stored_challenge = "challenge123";
    ///
    /// let assertion = Assertion::from_base64("omlzaWduYXR1cmVYRzBFAiEA3P1gbUuJK9dipE03PXibJgDMDJ3BeFp3NDtSL9U5sXECIHn4VZOXWpHpTP8WEXdqiqDQXGYpmEzmFwjlAa2Z7FkScWF1dGhlbnRpY2F0b3JEYXRhWCWkXNlsBrqJ4mRKrRfpKJTm48XHMxXQ8W64SUf50/HoU0AAAAAB").unwrap();
    ///
    /// match assertion.verify(client_data_json, app_id, public_key_bytes, previous_counter, stored_challenge) {
    ///     Ok(_) => println!("Verification successful!"),
    ///     Err(e) => println!("Verification failed: {}", e),
    /// }
    /// ```
    pub fn verify(self, client_data_byte: Vec<u8>, app_id: &str, public_key_byte: Vec<u8>, previous_counter: u32, stored_challenge: &str) -> Result<(), Box<dyn Error>> {
        let client_data  = serde_json::from_slice::<ClientData>(&client_data_byte)?;

        let auth_data = AuthenticatorData::new(self.raw_authenticator_data)?;

        // 1. Compute clientDataHash as the SHA256 hash of clientData.
        let mut hasher = Sha256::new();
        hasher.update(&client_data_byte);
        let client_data_hash = hasher.finalize();

        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_byte)
            .map_err(|_| AppAttestError::Message("failed to parse the public key".to_string()))?;

        // 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
        let mut hasher = Sha256::new();
        hasher.update(auth_data.bytes.as_slice());
        hasher.update(client_data_hash.as_slice());
        let nonce_hash = hasher.finalize();

        let signature = ecdsa::Signature::from_der(&self.signature)
            .map_err(|_| AppAttestError::Message("invalid signature format".to_string()))?;

        // 3. Use the public key that you store from the attestation object to verify that the assertion’s signature is valid for nonce.
        if verifying_key.verify(nonce_hash.as_slice(), &signature).is_err() {
            return Err(Box::new(AppAttestError::InvalidSignature));
        }

        // 4. Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
        auth_data.verify_app_id(app_id)?;

        // 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
        if auth_data.counter <= previous_counter {
            return Err(Box::new(AppAttestError::InvalidCounter));
        }
 
        // 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
        if stored_challenge != client_data.challenge {
            return Err(Box::new(AppAttestError::Message("challenge mismatch".to_string())));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
   
    #[test]
    fn test_from_base64_valid() {
        let valid_cbor_base64 = "omlzaWduYXR1cmVYRjBEAiAImFuY4+UbGZ5/ZbjAJpjQ3bd8GxaKFpMEo58WMEUGbwIgaqdDJnVS8/3oJCz16O5Zp4Qga5g6zrFF7eoiYEWkdtNxYXV0aGVudGljYXRvckRhdGFYJaRc2WwGuoniZEqtF+kolObjxcczFdDxbrhJR/nT8ehTQAAAAAI=";
        let result = Assertion::from_base64(valid_cbor_base64);
        assert!(result.is_ok());
    }
}