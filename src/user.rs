use hex::ToHex;
use log::{info, warn};
use ring::{rand::SecureRandom, signature::{KeyPair, VerificationAlgorithm}};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{server, util, ConsensusError, ConsensusReq, ConsensusRes, ConsensusToken, InstanceState};

/// Handle user login requests
pub async fn user_login(state: &InstanceState, email: String, password: String) -> ConsensusRes {
    let row = match sqlx::query("SELECT * FROM users WHERE email = ?1;")
        .bind(&email)
        .fetch_one(&state.db_pool).await {
        Ok(row) => {row},
        Err(_) => {
            info!("Login attempt from {}... - Failure, User not registered", {let mut e = email.clone(); e.truncate(9); e});
            return ConsensusRes::Login { res: Err("User not registered".into()) };
        },
    };

    // TODO: password verification
    let password_salt: String = row.get("salt");
    let mut hasher = Sha256::new();
    hasher.update(password + &password_salt);
    let password_hash = hex::encode(hasher.finalize());
    let expected_hash: String = row.get("password");

    if password_hash != expected_hash {
        info!("Login attempt from {}... - Failure, Password or Email incorrect", {let mut e = email.clone(); e.truncate(9); e});
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        return ConsensusRes::Login { res: Err("Password or Email incorrect".into()) };
    }

    let id: String = row.get("id");
    let username: String = row.get("username");
    let email: String = row.get("email");
    let authkey: String = row.get("authkey_private");

    info!("Login attempt from {}... - Success", {let mut e = email.clone(); e.truncate(9); e});
    ConsensusRes::Login { res: Ok(("localhost:3000".into(), id, username, email, authkey)) }
}

/// Handle user registration requests
pub async fn user_register(state: &InstanceState, username: String, email: String, password: String) -> ConsensusRes {
    // does user exist?
    match sqlx::query("SELECT * FROM users WHERE email = ?1;")
        .bind(&email)
        .fetch_one(&state.db_pool).await {
        Ok(_) => {
            info!("Registration attempt from {}... - Failure, Email in use", {let mut e = email.clone(); e.truncate(9); e});
            return ConsensusRes::Login { res: Err("Email in use".into()) };
        },
        Err(_) => {},
    };

    // TODO: make this amateur cryptography not horrifically insecure.
    // create signature Ed25519 key pair
    let genk: ring::pkcs8::Document = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let genk = genk.as_ref();
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(genk).unwrap();
    let auth_key_public: String = key_pair.public_key().encode_hex();
    let auth_key_private: String = hex::encode(genk);

    let id = crate::util::gen_uid_256();
    let time_registered = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // salt and hash password
    let mut salt = vec![0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut salt).unwrap();
    let password_salt = hex::encode(salt);
    let mut hasher = Sha256::new();
    hasher.update(password + &password_salt);
    let password_hash = hex::encode(hasher.finalize());


    sqlx::query("INSERT INTO users (id, username, email, password, salt, validated, authkey_public, authkey_private, registered) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);")
        .bind(&id)
        .bind(&username)
        .bind(&email)
        .bind(password_hash)
        .bind(password_salt)
        .bind(false)
        .bind(auth_key_public)
        .bind(auth_key_private)
        .bind(time_registered)
        .execute(&state.db_pool).await.unwrap();

    info!("Registration attempt from {}... - Success", {let mut e = email.clone(); e.truncate(9); e});
    ConsensusRes::Login { res: Ok(("localhost:3000".into(), id, username, email, "0".into())) }
}

/// Handle a user request for a token
pub async fn user_request_token(state: &InstanceState, instance: String, id: String, signature: String) -> ConsensusRes {
    let ids = {let mut i = id.clone(); i.truncate(9); i};
    info!("Token request {} - requesting authkey from {}", ids, instance);
    let res = server::make_req(&state, &instance, ConsensusReq::ReqUserKey { user_id: id.clone() } ).await;

    let key = match res {
        Ok(res) => {
            match res {
                ConsensusRes::UserKey { res } => {
                    match res {
                        Ok(key) => {
                            match hex::decode(key) {
                                Ok(k) => k,
                                Err(_) => {
                                    warn!("Token request with malformed authentication key.");
                                    return ConsensusRes::Token { res: Err(ConsensusError::Rejected) }; },
                            }
                        },
                        Err(e) => {return ConsensusRes::Token { res: Err(e) }},
                    }
                },
                _ => {
                    warn!("Token request with unexpected response from sign-on instance.");
                    return ConsensusRes::Token { res: Err(ConsensusError::Rejected) }; }
            }
        },
        Err(e) => {
            warn!("Token request with error from sign-on instance: {}", e);
            return ConsensusRes::Token { res: Err(ConsensusError::Rejected) }
        },
    };

    let msg = instance.clone() + &id;
    let sig = match hex::decode(signature) {
        Ok(s) => s,
        Err(_) => {
            warn!("Token request {} - malformed signature.", ids);
            return ConsensusRes::Token { res: Err(ConsensusError::Rejected) };
        },
    };

    info!("Token request {} - verifying authkey", ids);
    match ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key).verify(msg.as_bytes(), &sig) {
        Ok(_) => (),
        Err(_) => {
            warn!("Token request {} - wrong authentication key.", ids);
            return ConsensusRes::Token { res: Err(ConsensusError::Rejected) };
        },
    }

    // User validated, generate and send token.
    let token = util::gen_uid_512();
    let time_created = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let time_valid = chrono::Utc::now().checked_add_days(chrono::Days::new(1)).unwrap().format("%Y-%m-%d %H:%M:%S").to_string();

    sqlx::query("INSERT INTO tokens (token, user_id, user_instance, created, valid) VALUES (?1, ?2, ?3, ?4, ?5);")
        .bind(&token)
        .bind(&id)
        .bind(instance)
        .bind(time_created)
        .bind(&time_valid)
        .execute(&state.db_pool).await.unwrap();

    info!("Token request {} - Success", ids);
    ConsensusRes::Token { res: Ok(ConsensusToken { token, valid_until: time_valid }) }
} 