use appattest_rs::assertion::Assertion;
use base64::{engine::general_purpose, Engine};

fn main() {
    let client_data_json = r#"{"challenge": "challenge123"}"#.as_bytes().to_vec();
    let app_id = "<APPLE_TEAM_ID>.<APPLE_APP_ID>"; // replace this with yours. E.g 9000738U8.auth.iphone.com
    let public_key_base64 = "BLROJkpk8NoHVHAnkLOKWUrc4MhyMkATpDyDwjEk82o+uf+KCQiDoHZdlcJ1ff5HPgK7Jd/pTA3cyKOq5MYM6Gs=";
    let public_key_byte = general_purpose::STANDARD.decode(public_key_base64).expect("unable to decode public key");

    let previous_counter = 0;
    let stored_challenge = "5b3b2303-e650-4a56-a9ec-33e3e2a90d14";
    let base64_cbor_data = "omlzaWduYXR1cmVYRjBEAiAImFuY4+UbGZ5/ZbjAJpjQ3bd8GxaKFpMEo58WMEUGbwIgaqdDJnVS8/3oJCz16O5Zp4Qga5g6zrFF7eoiYEWkdtNxYXV0aGVudGljYXRvckRhdGFYJaRc2WwGuoniZEqtF+kolObjxcczFdDxbrhJR/nT8ehTQAAAAAI=";

    // Convert from base64 CBOR to Assertion
    let assertion_result = Assertion::from_base64(base64_cbor_data);
    
    match assertion_result {
        Ok(assertion) => {
            match assertion.verify(client_data_json, app_id, public_key_byte, previous_counter, stored_challenge) {
                Ok(_) => println!("Verification successful!"),
                Err(e) => println!("Verification failed: {:?}", e),
            }
        },
        Err(e) => println!("Failed to decode and create assertion: {:?}", e),
    }
}
