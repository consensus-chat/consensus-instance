use log::info;
use ring::rand::SecureRandom;
use sqlx::{Pool, Sqlite};

/// Generate a unique 64-bit id
pub fn gen_uid_64() -> String {
    let mut data = vec![0u8; 64/8];
    ring::rand::SystemRandom::new().fill(&mut data).unwrap();
    hex::encode(data)
}

/// Generate a unique 128-bit id
pub fn gen_uid_128() -> String {
    let mut data = vec![0u8; 128/8];
    ring::rand::SystemRandom::new().fill(&mut data).unwrap();
    hex::encode(data)
}

/// Generate a unique id 256-bit
pub fn gen_uid_256() -> String {
    let mut data = vec![0u8; 256/8];
    ring::rand::SystemRandom::new().fill(&mut data).unwrap();
    hex::encode(data)
}

pub async fn sanitize_db(db_pool: &Pool<Sqlite>) {
    info!("Sanitizing database");
    // remove old tokens
    let time_now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query("DELETE FROM tokens WHERE valid < ?1;")
        .bind(time_now)
        .execute(db_pool).await.unwrap();
}