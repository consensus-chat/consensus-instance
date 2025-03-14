use axum::{
    extract::{self, State}, http::StatusCode, response::{Html, IntoResponse}, routing::{get, post}, Json, Router
};

use tower_http::services::{ServeDir, ServeFile};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};

mod protocol;
mod user;
mod util;

pub use protocol::*;

#[tokio::main]
async fn main() {
    // Database
    let db_pool: sqlx::Pool<sqlx::Sqlite> = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("db/database.sqlite").await.unwrap();

    // Web dir for simple front page
    let serve_dir = ServeDir::new("web")
        .not_found_service(ServeFile::new("web/404.html"));

    let app = Router::new()
        .route("/register", post(user::handler_register))
        .route("/login", post(user::handler_login))
        .route("/", post(handler))
        .fallback_service(serve_dir)
        .with_state(db_pool);

    

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Handle all application requests
pub async fn handler(State(db_pool): State<Pool<Sqlite>>, extract::Json(payload): extract::Json<ConsensusReq>) -> Json<ConsensusRes> {
    Json(match payload {
        ConsensusReq::Login { email, password } => user::user_login(db_pool, email, password).await,
    })
}