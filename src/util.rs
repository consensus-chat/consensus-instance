use std::time;

use sha2::{Sha256, Sha512, Digest};

/// Generate a unique id from input parameters and the time
pub fn gen_uid_256(inp: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(inp + &time::SystemTime::now().duration_since(time::UNIX_EPOCH).expect("time travel").as_secs().to_string()
    );
    hex::encode(&hasher.finalize()[..])
}

/// Generate a unique id from input parameters and the time
pub fn gen_uid_512(inp: String) -> String {
    let mut hasher = Sha512::new();
    hasher.update(inp + &time::SystemTime::now().duration_since(time::UNIX_EPOCH).expect("time travel").as_secs().to_string()
    );
    hex::encode(&hasher.finalize()[..])
}