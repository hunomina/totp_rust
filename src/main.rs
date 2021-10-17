use hmacsha1::hmac_sha1;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};

const TOTP_VALIDITY_DURATION: u128 = 30000; // 30 seconds
const TOTP_LENGTH: u32 = 6;

fn main() {
    let _key = generate_key(30);
    let key = String::from("LbfGTsah9e2cpKWgCMvDUkvdz2Fx2p");

    // tools like Google Authenticator usually accept base32 encoded keys
    // let encoded_key = base32::encode(base32::Alphabet::Crockford, key.as_bytes());
    // println!("encoded key {}", encoded_key);

    loop {
        let totp = generate_htop(key.clone(), get_counter());
        println!("totp {:06}", totp);
        thread::sleep(time::Duration::from_millis(TOTP_VALIDITY_DURATION as u64));
    }
}

fn generate_key(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

// transforms the counter into a message for hmac algorithm
// extracts bits 8 by 8, starting from the end of the slice
// counter is u128 like timestamp
fn create_message_from_counter(mut counter: u128) -> [u8; 8] {
    let mut buff = [0; 8];
    for i in 0..8 {
        buff[7 - i] = (counter & 0xff) as u8;
        counter = counter >> 8;
    }
    buff
}

fn compute_dynamic_truncation(bytes: &[u8]) -> u32 {
    let bytes = bytes.to_vec();
    // create a dynamic offset
    // by truncating the 4 last bits (0xf == 0b1111 -> 4 bits) from the last item of the byte slice
    // and convert it into an integer
    // so 0 <= offset <= 15
    let offset = (bytes[bytes.len() - 1] & 0xf) as usize;
    (((bytes[offset] & 0x7f) as u32) << 24)
        | (((bytes[offset + 1] & 0xff) as u32) << 16)
        | (((bytes[offset + 2] & 0xff) as u32) << 8)
        | (bytes[offset + 3] & 0xff) as u32
}

fn generate_htop(key: String, counter: u128) -> u32 {
    let message = create_message_from_counter(counter);
    let hmac_value = hmac_sha1(key.as_bytes(), &message);
    let dynamic_truncation = compute_dynamic_truncation(&hmac_value);

    // trim the last TOTP_LENGTH digits from dynamic truncation
    dynamic_truncation % 10u32.pow(TOTP_LENGTH)
}

fn current_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Could not get the current timestamp")
        .as_millis()
}

fn get_counter() -> u128 {
    // divide by TOTP_VALIDITY_DURATION,
    // so that for a given timestamp, the counter would be the same for a duration of TOTP_VALIDITY_DURATION
    current_timestamp() / TOTP_VALIDITY_DURATION
}

// https://datatracker.ietf.org/doc/html/rfc4226
// https://datatracker.ietf.org/doc/html/rfc6238
// note : HTOP uses hmac-sha-1 but TOTP "may use" hmac-sha-256 (see TOTP rfc)