use axum::{extract::State, http::StatusCode, response::IntoResponse};
use sqlx::{Pool, Sqlite};

// Registers a new user
pub async fn handler_register(State(db_pool): State<Pool<Sqlite>>, body: String) -> impl IntoResponse {
    let req: Vec<&str> = body.split('&').collect();
    let username;
    if req[0].starts_with("uname=") {
        username = req[0].replacen("uname=", "", 1);
    } else {
        return StatusCode::BAD_REQUEST;
    };
    let email;
    if req[1].starts_with("mail=") {
        email = req[1].replacen("mail=", "", 1);
    } else {
        return StatusCode::BAD_REQUEST;
    };
    
    let id = crate::util::gen_uid_256(username.to_string() + &email);
    let time_registered = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    sqlx::query("INSERT INTO users (id, username, email, validated, authkey_public, authkey_private, registered) VALUES ($1, $2, $3, $4, $5, $6, $7);")
        .bind(id)
        .bind(username)
        .bind(email)
        .bind(false)
        .bind("0")
        .bind("0")
        .bind(time_registered)
        .execute(&db_pool).await.unwrap();

    return StatusCode::ACCEPTED;
}

// Returns a users key if login was successful
pub async fn handler_login(body: String) -> impl IntoResponse {
    println!("{}", body)
}