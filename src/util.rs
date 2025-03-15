use ring::rand::SecureRandom;

/// Generate a unique id from input parameters and the time
pub fn gen_uid_256() -> String {
    let mut data = vec![0u8; 256];
    ring::rand::SystemRandom::new().fill(&mut data).unwrap();
    hex::encode(data)
}

/// Generate a unique id from input parameters and the time
pub fn gen_uid_512() -> String {
    let mut data = vec![0u8; 512];
    ring::rand::SystemRandom::new().fill(&mut data).unwrap();
    hex::encode(data)
}