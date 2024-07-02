use byteorder::{BigEndian, ByteOrder};
use sha2::{Sha256, Digest};
use std::error::Error;
use crate::error::AppAttestError;

 #[allow(dead_code)]
pub(crate) struct AuthenticatorData {
    pub(crate) bytes: Vec<u8>,
    pub(crate) rp_id_hash: Vec<u8>,
    pub(crate) flags: u8,
    pub(crate) counter: u32,
    pub(crate) aaguid: Option<AAGUID>, 
    pub(crate) credential_id: Option<Vec<u8>>,
}

impl AuthenticatorData {
    pub(crate) fn new(auth_data_byte: Vec<u8>) -> Result<Self, AppAttestError> {
        if auth_data_byte.len() < 37 {
            return Err(AppAttestError::Message("Authenticator data is too short".to_string()));
        }

        let mut auth_data = AuthenticatorData {
            bytes: auth_data_byte.clone(),
            rp_id_hash: auth_data_byte[0..32].to_vec(),
            flags: auth_data_byte[32],
            counter: BigEndian::read_u32(&auth_data_byte[33..37]),
            aaguid: None,
            credential_id: None,
        };

        auth_data.populate_optional_data().map_err(|e| AppAttestError::Message(e.to_string()))?;

        Ok(auth_data)
    }
    fn populate_optional_data(&mut self) -> Result<(), Box<dyn Error>>{
        if self.bytes.len() < 55 {
            return Ok(());
        }

        let length = BigEndian::read_u16(&self.bytes[53..55]) as usize;
        let credential_id = self.bytes[55..55 + length].to_vec();
        let aaguid = AAGUID::new(self.bytes[37..53].to_vec())?;

        self.credential_id = Some(credential_id);
        self.aaguid = Some(aaguid);

        Ok(())
    }
    pub(crate) fn is_valid_aaguid(&self) -> bool {
        let expected_aaguid = APP_ATTEST.as_bytes().to_vec();
        let mut prod_aaguid = expected_aaguid.clone();
        prod_aaguid.extend(std::iter::repeat(0x00).take(7));
       
        if let Some(aaguid) = &self.aaguid {
            return aaguid.bytes() == expected_aaguid || aaguid.bytes() == prod_aaguid
        }

        false
    }

    pub(crate) fn verify_counter(&self) -> Result<(), AppAttestError> {
        if self.counter != 0 {
            return Err(AppAttestError::InvalidCounter)
        }
        Ok(())
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
        if let Some(credential_id) = &self.credential_id {
            if credential_id == key_id {
                return Ok(());
            } 
        }
        Err(AppAttestError::InvalidCredentialID)
    }
}

pub(crate) struct AAGUID(String);

const APP_ATTEST: &str = "appattest";
const APP_ATTEST_DEVELOP: &str = "appattestdevelop";

impl AAGUID {
    fn new(b: Vec<u8>) -> Result<Self, AppAttestError> {
        let ids: [&str; 2] = [APP_ATTEST, APP_ATTEST_DEVELOP];
        for &id in ids.iter() {
            if id.as_bytes() == AAGUID::trim_trailing_zeros(b.as_slice()) {
                return Ok(AAGUID(id.to_string()));
            }
        }
        Err(AppAttestError::InvalidAAGUID)
    }

    fn bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
        let mut last_non_zero = None;
        for (index, &value) in bytes.iter().enumerate() {
            if value != 0 {
                last_non_zero = Some(index);
            }
        }
    
        match last_non_zero {
            Some(index) => &bytes[..=index],
            None => &[],  
        }
    }
    
}
