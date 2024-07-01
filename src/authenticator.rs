use byteorder::{BigEndian, ByteOrder};
use sha2::{Sha256, Digest};
use crate::error::AppAttestError;

pub(crate) struct AuthenticatorData {
    pub(crate) bytes: Vec<u8>,
    pub(crate) rp_id_hash: Vec<u8>,
    pub(crate) flags: u8,
    pub(crate) counter: u32,
    pub(crate) aaguid: AAGUID, 
    pub(crate) credential_id: Vec<u8>,
}

impl AuthenticatorData {
    pub(crate) fn new(auth_data_byte: Vec<u8>) -> Result<Self, AppAttestError> {
        if auth_data_byte.len() < 37 {
            return Err(AppAttestError::Message("Authenticator data is too short".to_string()));
        }

        if auth_data_byte.len() < 55 {
            return Err(AppAttestError::Message("Insufficient data for credential ID and AAGUID".to_string()));
        }

        let length = BigEndian::read_u16(&auth_data_byte[53..55]) as usize;
        if 55 + length > auth_data_byte.len() {
            return Err(AppAttestError::Message("Credential ID slice out of bounds".to_string()));
        }
        let credential_id = auth_data_byte[55..55 + length].to_vec();
        let aaguid = AAGUID::new(auth_data_byte[37..53].to_vec())?;

        let auth_data = AuthenticatorData {
            bytes: auth_data_byte.clone(),
            rp_id_hash: auth_data_byte[0..32].to_vec(),
            flags: auth_data_byte[32],
            counter: BigEndian::read_u32(&auth_data_byte[33..37]),
            aaguid,
            credential_id,
        };

        Ok(auth_data)
    }

    pub(crate) fn is_valid_aaguid(&self) -> bool {
        let expected_aaguid = APP_ATTEST.as_bytes().to_vec();
        let mut prod_aaguid = expected_aaguid.clone();
        prod_aaguid.extend(std::iter::repeat(0x00).take(7));

        self.aaguid.bytes() == expected_aaguid || self.aaguid.bytes() == prod_aaguid
    }

    pub(crate) fn verify_counter(&self) -> Result<(), AppAttestError> {
        if self.counter == 0 {
            Err(AppAttestError::InvalidCounter)
        } else {
            Ok(())
        }
    }

    pub(crate) fn verify_app_id(&self, app_id: &str) -> Result<(), AppAttestError> {
        let mut hasher = Sha256::new();
        hasher.update(app_id.as_bytes());
        if self.rp_id_hash != hasher.finalize().as_slice() {
            Err(AppAttestError::InvalidAppID)
        } else {
            Ok(())
        }
    }

    pub(crate) fn verify_key_id(&self, key_id: &Vec<u8>) -> Result<(), AppAttestError> {
        if &self.credential_id != key_id {
            Err(AppAttestError::InvalidCredentialID)
        } else {
            Ok(())
        }
    }
}

struct AAGUID(String);

const APP_ATTEST: &str = "appattest";
const APP_ATTEST_DEVELOP: &str = "appattestdevelop";

impl AAGUID {
    fn new(b: Vec<u8>) -> Result<Self, AppAttestError> {
        let ids: [&str; 2] = [APP_ATTEST, APP_ATTEST_DEVELOP];
        for &id in ids.iter() {
            if id.as_bytes() == b.as_slice() {
                return Ok(AAGUID(id.to_string()));
            }
        }
        Err(AppAttestError::InvalidAAGUID)
    }

    fn bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}
