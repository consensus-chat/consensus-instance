use hex::ToHex;
use log::{info, warn};
use ring::{rand::SecureRandom, signature::KeyPair};
use sha2::{Digest, Sha256};
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::{
    server, util, ConsensusError, ConsensusReq, ConsensusRes, ConsensusToken, InstanceState, ServerData, SyncedUserData
};

async fn user_registered(state: &InstanceState, uid: &str) -> bool {
    match sqlx::query("SELECT * FROM users WHERE id = ?1;")
        .bind(uid)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(_) => return true,
        Err(_) => return false,
    }
}

/// Handle user login requests
pub async fn login(state: &InstanceState, email: String, password: String) -> ConsensusRes {
    let ems = {let mut e = email.clone(); e.truncate(9); e};
    let row = match sqlx::query("SELECT * FROM users WHERE email = ?1;")
        .bind(&email)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(row) => row,
        Err(_) => {
            info!("Login attempt from {}... - Failure, User not registered", ems);
            return ConsensusRes::Error(ConsensusError::NotFound);
        }
    };

    // TODO: password verification
    let password_salt: String = row.get("salt");
    let mut hasher = Sha256::new();
    hasher.update(password + &password_salt);
    let password_hash = hex::encode(hasher.finalize());
    let expected_hash: String = row.get("password");

    if password_hash != expected_hash {
        info!("Login attempt from {}... - Failure, Password or Email incorrect", ems);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        return ConsensusRes::Error(ConsensusError::Incorrect);
    }

    let id: String = row.get("id");
    let username: String = row.get("username");
    let email: String = row.get("email");
    let authkey: String = row.get("authkey_private");

    info!("Login attempt from {}... - Success", ems);
    ConsensusRes::Login(state.config.domain.clone(), id, username, email, authkey)
}

/// Handle user registration requests
pub async fn register(
    state: &InstanceState,
    username: String,
    email: String,
    password: String,
) -> ConsensusRes {
    let ems = {let mut e = email.clone(); e.truncate(9); e};
    // does user exist?
    match sqlx::query("SELECT * FROM users WHERE email = ?1;")
        .bind(&email)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(_) => {
            info!("Registration attempt from {}... - Failure, Email in use", ems);
            return ConsensusRes::Error(ConsensusError::EmailInUse);
        }
        Err(_) => {}
    };

    // TODO: make this amateur cryptography not horrifically insecure.
    // create signature Ed25519 key pair
    let genk: ring::pkcs8::Document =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
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

    sqlx::query("INSERT INTO users (id, username, email, password, salt, validated, authkey_public, authkey_private, registered, last_synced) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);")
        .bind(&id)
        .bind(&username)
        .bind(&email)
        .bind(password_hash)
        .bind(password_salt)
        .bind(false)
        .bind(auth_key_public)
        .bind(&auth_key_private)
        .bind(&time_registered)
        .bind(&time_registered)
        .execute(&state.db_pool).await.unwrap();

    info!("Registration attempt from {}... - Success", ems);
    ConsensusRes::Login(state.config.domain.clone(), id, username, email, auth_key_private)
}

/// Handle a user request for a token
pub async fn request_token(
    state: &InstanceState,
    instance: String,
    id: String,
    signature: String,
) -> ConsensusRes {
    let ids = {
        let mut i = id.clone();
        i.truncate(9);
        i
    };
    info!("Token request {} - requesting authkey from {}", ids, instance );
    let res = server::make_req(
        &state,
        &instance,
        ConsensusReq::InstReqUserKey {
            user_id: id.clone(),
        },
    )
    .await;

    let key = match res {
        Ok(res) => match res {
            ConsensusRes::UserKey(key) => match hex::decode(key) {
                Ok(k) => k,
                Err(_) => {
                    warn!("Token request with malformed authentication key.");
                    return ConsensusRes::Error(ConsensusError::Rejected);
                }
            },
            _ => {
                warn!("Token request with unexpected response from sign-on instance.");
                return ConsensusRes::Error(ConsensusError::Rejected);
            }
        },
        Err(e) => {
            warn!("Token request with error from sign-on instance: {}", e);
            return ConsensusRes::Error(ConsensusError::Rejected);
        }
    };

    let msg = instance.clone() + &id;
    let sig = match hex::decode(signature) {
        Ok(s) => s,
        Err(_) => {
            warn!("Token request {} - malformed signature.", ids);
            return ConsensusRes::Error(ConsensusError::Rejected);
        }
    };

    info!("Token request {} - verifying authkey", ids);
    match ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(msg.as_bytes(), &sig)
    {
        Ok(_) => (),
        Err(_) => {
            warn!("Token request {} - wrong authentication key.", ids);
            return ConsensusRes::Error(ConsensusError::Rejected);
        }
    }

    // User validated, generate and send token.
    let token = util::gen_uid_256();
    let time_created = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let time_valid = chrono::Utc::now()
        .checked_add_days(chrono::Days::new(1))
        .unwrap()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    sqlx::query("INSERT INTO tokens (token, user_id, user_instance, created, valid) VALUES (?1, ?2, ?3, ?4, ?5);")
        .bind(&token)
        .bind(&id)
        .bind(instance)
        .bind(time_created)
        .bind(&time_valid)
        .execute(&state.db_pool).await.unwrap();

    info!("Token request {} - Success", ids);
    ConsensusRes::Token(ConsensusToken {
        token,
        valid_until: time_valid,
    })
}

async fn get_db_user_data(state: &InstanceState, uid: &str) -> SyncedUserData {
    let row_user = sqlx::query("SELECT * FROM users WHERE id = ?1;")
        .bind(&uid)
        .fetch_one(&state.db_pool)
        .await
        .unwrap();

    let rows_servers = sqlx::query("SELECT * FROM user_servers WHERE user_id = ?1;")
        .bind(&uid)
        .fetch_all(&state.db_pool)
        .await
        .unwrap();
    let mut servers = vec![];

    for r in rows_servers {
        servers.push(ServerData {
            name: r.get("server_name"),
            instance: r.get("server_instance"),
            id: r.get("server_id"),
        });
    }

    SyncedUserData {
        last_synced: row_user.get("last_synced"),
        display_name: row_user.get("username"),
        status: row_user.get("status"),
        pronouns: row_user.get("pronouns"),
        bio: row_user.get("bio"),
        servers,
    }
}

async fn set_db_user_data(state: &InstanceState, uid: &str, data: &SyncedUserData) {
    sqlx::query("UPDATE users SET username = ?1, status = ?2, pronouns = ?3, bio = ?4, last_synced = ?5 WHERE id = ?6;")
        .bind(&data.display_name)
        .bind(&data.status)
        .bind(&data.pronouns)
        .bind(&data.bio)
        .bind(&data.last_synced)
        .bind(uid)
        .execute(&state.db_pool).await.unwrap();

    sqlx::query("DELETE FROM user_servers WHERE user_id = ?1;")
        .bind(uid)
        .execute(&state.db_pool).await.unwrap();

    let mut query_builder: QueryBuilder<Sqlite> = QueryBuilder::new("INSERT INTO user_servers (user_id, server_id, server_instance, server_name) ");
    query_builder.push_values(data.servers.clone(), |mut b, s| {
        b.push_bind(uid)
            .push_bind(s.id)
            .push_bind(s.instance)
            .push_bind(s.name);
    });
    let query = query_builder.build();
    query.execute(&state.db_pool).await.unwrap();
}

/// A registered user requests their user data from this instance
pub async fn request_user_data(state: &InstanceState, token: String) -> ConsensusRes {
    info!("User data request");
    let (uid, uinstance) = match val_token(state, &token).await {
        Ok(user) => user,
        Err(_) => return ConsensusRes::Error(ConsensusError::NotAuthorised),
    };

    if !(uinstance == state.config.domain) {
        return ConsensusRes::Error(ConsensusError::NotFound)
    }

    if !(user_registered(state, &uid).await) {
        return ConsensusRes::Error(ConsensusError::NotFound)
    }

    let data = get_db_user_data(state, &uid).await;
    ConsensusRes::SyncedUserData(data)
}

/// A registered user requests user data synchronization
pub async fn sync_user_data(state: &InstanceState, token: String, data: SyncedUserData) -> ConsensusRes {
    info!("User data sync request");
    let (uid, uinstance) = match val_token(state, &token).await {
        Ok(user) => user,
        Err(_) => return ConsensusRes::Error(ConsensusError::NotAuthorised),
    };

    if !(uinstance == state.config.domain) {
        return ConsensusRes::Error(ConsensusError::NotFound)
    }

    if !(user_registered(state, &uid).await) {
        return ConsensusRes::Error(ConsensusError::NotFound)
    }

    let server_data = get_db_user_data(state, &uid).await;
    let s_last_sync = chrono::NaiveDateTime::parse_from_str(&server_data.last_synced, "%Y-%m-%d %H:%M:%S").unwrap().and_utc();
    let c_last_sync = chrono::NaiveDateTime::parse_from_str(&data.last_synced, "%Y-%m-%d %H:%M:%S").unwrap().and_utc();
    let client_outdated = c_last_sync < s_last_sync;

    let mut new_data = SyncedUserData {
        last_synced: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        display_name: server_data.display_name,
        status: server_data.status,
        pronouns: server_data.pronouns,
        bio: server_data.bio,
        servers: vec![],
    };

    if client_outdated {
        new_data.servers = server_data.servers;
    } else {
        new_data.servers = data.servers;
    }

    set_db_user_data(state, &uid, &new_data).await;

    ConsensusRes::SyncedUserData(new_data)
}

pub async fn val_token(state: &InstanceState, token: &str) -> Result<(String, String), ()> {
    let row = match sqlx::query("SELECT * FROM tokens WHERE token = ?1 ORDER BY valid DESC LIMIT 1;")
        .bind(&token)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            info!("Failed to validate token - {}", e);
            return Err(())
        }
    };
    let valid: String = row.get("valid");
    let t = chrono::NaiveDateTime::parse_from_str(&valid, "%Y-%m-%d %H:%M:%S").unwrap();

    if t.and_utc() > chrono::Utc::now() {
        let uid: String = row.get("user_id");
        let uinstance: String = row.get("user_instance");

        Ok((uid, uinstance))
    } else {
        info!("Authentication attempt with old token - {} too old", valid);
        Err(())
    }
}
