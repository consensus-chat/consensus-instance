use log::info;
use sqlx::Row;

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

pub async fn server_request_user_key(state: &InstanceState, user_id: String) -> ConsensusRes {
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
