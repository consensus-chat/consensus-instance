use axum::response::IntoResponse;
use log::info;
use sqlx::Row;
use tokio_util::io::ReaderStream;

use crate::user;
use crate::InstanceState;
use crate::protocol::*;

// Make a request to an instance
pub async fn make_req(
    state: &InstanceState,
    instance: &str,
    req: ConsensusReq,
) -> Result<ConsensusRes, String> {
    let res = match state
        .client
        .post(format!("http://{}", instance))
        .json(&req)
        .send()
        .await
    {
        Ok(res) => res,
        Err(_) => return Err(format!("Error connecting to '{}'", instance)),
    };

    match serde_json::from_str(&res.text().await.unwrap()) {
        Ok(req) => Ok(req),
        Err(_) => Err("Couldn't parse response. Is Instance correct and supported?".into()),
    }
}

pub async fn request_user_key(state: &InstanceState, user_id: String) -> ConsensusRes {
    let row = match sqlx::query("SELECT * FROM users WHERE id = ?1;")
        .bind(&user_id)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(row) => row,
        Err(_) => {
            info!("User key request {} - Failure, User not found", {
                let mut e = user_id.clone();
                e.truncate(9);
                e
            });
            return ConsensusRes::Error(ConsensusError::NotFound);
        }
    };
    let key: String = row.get("authkey_public");
    ConsensusRes::UserKey(key)
}

pub async fn create_server(state: &InstanceState, token: String, server_name: String) -> ConsensusRes {
    info!("Creating server {}", server_name);
    if !state.config.servers.allow_server_creation {
        return ConsensusRes::Error(ConsensusError::Rejected);
    }

    let (uid, uinstance) = match user::val_token(state, &token).await {
        Ok(user) => user,
        Err(_) => return ConsensusRes::Error(ConsensusError::NotAuthorised),
    };

    let sid = crate::util::gen_uid_64();
    let time_created = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    sqlx::query("INSERT INTO servers (id, name, admin_id, admin_instance, time_created) VALUES (?1, ?2, ?3, ?4, ?5);")
        .bind(&sid)
        .bind(&server_name)
        .bind(&uid)
        .bind(&uinstance)
        .bind(time_created)
        .execute(&state.db_pool).await.unwrap();

    sqlx::query("INSERT INTO server_members (user_instance, user_id, server_id) VALUES (?1, ?2, ?3);")
        .bind(&uinstance)
        .bind(&uid)
        .bind(&sid)
        .execute(&state.db_pool).await.unwrap();

    let cid = crate::util::gen_uid_256();

    sqlx::query("INSERT INTO channels (id, server_id, name) VALUES (?1, ?2, ?3);")
        .bind(&cid)
        .bind(&sid)
        .bind("general")
        .execute(&state.db_pool).await.unwrap();

    info!("Created server {}", server_name);
    ConsensusRes::ServerJoin(sid)
}

pub async fn join_server(state: &InstanceState, token: String, server_id: String) -> ConsensusRes {
    let (uid, uinstance) = match user::val_token(state, &token).await {
        Ok(user) => user,
        Err(_) => return ConsensusRes::Error(ConsensusError::NotAuthorised),
    };

    match sqlx::query("SELECT * FROM servers WHERE id = ?1;")
        .bind(&server_id)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(_) => {},
        Err(_) => {
            info!("Server join request failed: Server {} does not exist", server_id);
            return ConsensusRes::Error(ConsensusError::NotFound)
        }
    }

    match sqlx::query("SELECT * FROM server_members WHERE user_instance = ?1 AND user_id = ?2 AND server_id = ?3 LIMIT 1;")
        .bind(&uinstance)
        .bind(&uid)
        .bind(&server_id)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(_) => {
            info!("Server join request failed: User {} already server member of server {}", uid, server_id);
            return ConsensusRes::ServerJoin(server_id)
        },
        Err(_) => {}
    }

    sqlx::query("INSERT INTO server_members (user_instance, user_id, server_id) VALUES (?1, ?2, ?3);")
        .bind(&uinstance)
        .bind(&uid)
        .bind(&server_id)
        .execute(&state.db_pool).await.unwrap();

    info!("User {} joined server {}", uid, server_id);
    ConsensusRes::ServerJoin(server_id)
}

pub async fn request_server_data(state: &InstanceState, token: String, server_id: String) -> ConsensusRes {
    let (uid, uinstance) = match user::val_token(state, &token).await {
        Ok(user) => user,
        Err(_) => return ConsensusRes::Error(ConsensusError::NotAuthorised),
    };

    if !user_in_server(state, &uid, &uinstance, &server_id).await {
        return ConsensusRes::Error(ConsensusError::Rejected);
    }

    let row = match sqlx::query("SELECT * FROM servers WHERE id = ?1;")
        .bind(&server_id)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(row) => {row},
        Err(e) => {
            info!("Server data request failed: Server {} doesn't exist - {}", server_id, e);
            return ConsensusRes::Error(ConsensusError::Rejected)
        }
    };

    let name: String = row.get("name");

    ConsensusRes::ServerData(ServerData { name, instance: state.config.domain.clone(), id: server_id })
}

pub async fn request_server_structure(state: &InstanceState, token: String, server_id: String) -> ConsensusRes {
    let (uid, uinstance) = match user::val_token(state, &token).await {
        Ok(user) => user,
        Err(_) => return ConsensusRes::Error(ConsensusError::NotAuthorised),
    };

    if !user_in_server(state, &uid, &uinstance, &server_id).await {
        return ConsensusRes::Error(ConsensusError::NotAuthorised);
    }

    let rows = sqlx::query("SELECT * FROM channels WHERE server_id = ?1;")
        .bind(&server_id)
        .fetch_all(&state.db_pool)
        .await
        .unwrap();

    let mut sstruct = ServerStructure {
        channels: vec![]
    };

    for row in rows {
        let cname: String = row.get("name");
        let cid: String = row.get("id");
        sstruct.channels.push(ChannelList::Channel(Channel { name: cname, id: cid }));
    }

    return ConsensusRes::ServerStructure(sstruct);
}

/// Check if the user is a member of the instance server
async fn user_in_server(state: &InstanceState, uid: &str, uinstance: &str, sid: &str) -> bool {
    match sqlx::query("SELECT * FROM server_members WHERE user_instance = ?1 AND user_id = ?2 AND server_id = ?3 LIMIT 1;")
        .bind(&uinstance)
        .bind(&uid)
        .bind(&sid)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(_) => {
            return true;
        },
        Err(e) => {
            info!("Server request failed: User {} not server member or server {} doesn't exist - {}", uid, sid, e);
            return false;
        }
    }
}

/// Serve server icon
pub async fn server_img(sid: String) -> impl IntoResponse {
    let path = format!("img/s-{}.png", sid);
    let f = std::path::PathBuf::from(path.clone());
    let filename = match f.file_name() {
        Some(name) => name,
        None => return Err((axum::http::StatusCode::BAD_REQUEST, "File name couldn't be determined".to_string()))
    };
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(err) => return Err((axum::http::StatusCode::NOT_FOUND, format!("File not found: {}", err)))
    };

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let headers = [
        (axum::http::header::CONTENT_TYPE, "image/png".to_string()),
        (
            axum::http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{:?}\"", filename),
        ),
    ];
    
    return Ok((headers, body))
}
