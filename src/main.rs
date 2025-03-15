use std::fs::read_to_string;

use axum::{
    extract::{self, State}, routing::post, Json, Router
};

use log::{info, LevelFilter};
use log4rs::{append::{console::ConsoleAppender, file::FileAppender}, config::{Appender, Root}, encode::pattern::PatternEncoder};
use tower_http::services::{ServeDir, ServeFile};
use sqlx::sqlite::SqlitePoolOptions;

mod protocol;
mod user;
mod util;
mod server;

pub use protocol::*;

#[derive(serde::Deserialize)]
struct Config {
    name: String,
    port: i64,
    logging: CfgLog,
}

#[derive(serde::Deserialize)]
struct CfgLog {
    enable_file: bool,
    log_path: Option<String>,
    enable_stdout: bool,
    pattern: Option<String>,
    level: Option<String>,
}

#[derive(Clone)]
pub struct InstanceState {
    db_pool: sqlx::Pool<sqlx::Sqlite>,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    println!("Consensus Instance - v0.0.0");
    println!("Reading configuration...");
    let config_toml = match read_to_string("consensus.toml") {
        Ok(s) => s,
        Err(e) => {
            println!("Error reading config 'consensus.toml': {}", e);
            return;
        },
    };
    let config: Config = match toml::from_str(&config_toml) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing config: {}", e);
            return;
        },
    };

    // Setup logging
    if config.logging.enable_file || config.logging.enable_stdout {
        let pattern = match config.logging.pattern {
            Some(p) => p,
            None => "[{d(%Y-%m-%d %H:%M:%S)} {l}]: {m}{n}".into(),
        };
        let level = match config.logging.level {
            Some(l) => match l.as_str() {
                "Debug" => LevelFilter::Debug,
                "Error" => LevelFilter::Error,
                "Info" => LevelFilter::Info,
                "Off" => LevelFilter::Off,
                "Trace" => LevelFilter::Trace,
                "Warn" => LevelFilter::Warn,
                _ => {
                    println!("WARN: Logging level {} not recognised. Using Info", l);
                    LevelFilter::Info
                }
            },
            None => LevelFilter::Info,
        };

        let mut config_builder = log4rs::config::Config::builder();
        if config.logging.enable_file {
            let path = match config.logging.log_path {
                Some(p) => p,
                None => {
                        println!("ERROR: No log output path specified.");
                        return;
                    },
            };
            let fileout = FileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(&pattern)))
                .build(path)
                .unwrap();
            config_builder = config_builder.appender(Appender::builder().build("fileout", Box::new(fileout)));
        }
        if config.logging.enable_stdout {
            let stdout = ConsoleAppender::builder()
                .encoder(Box::new(PatternEncoder::new(&pattern)))
                .build();
            config_builder = config_builder.appender(Appender::builder().build("stdout", Box::new(stdout)))
        }

        let mut root_builder = Root::builder();
        if config.logging.enable_file {
            root_builder = root_builder.appender("fileout");
        }
        if config.logging.enable_file {
            root_builder = root_builder.appender("stdout");
        }
        
        let config = config_builder.build(root_builder.build(level)).unwrap();

        log4rs::init_config(config).unwrap();
    }
    info!("Starting Consensus instance");

    // Database
    let db_pool: sqlx::Pool<sqlx::Sqlite> = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("db/database.sqlite").await.unwrap();
    info!("Connected to database");

    let client = reqwest::Client::new();


    // Web dir for simple front page
    let serve_dir = ServeDir::new("web")
        .not_found_service(ServeFile::new("web/404.html"));

    let app = Router::new()
        .route("/", post(handler))
        .fallback_service(serve_dir)
        .with_state(InstanceState {
            db_pool,
            client
        });

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Handle all application requests
pub async fn handler(State(state): State<InstanceState>, extract::Json(payload): extract::Json<ConsensusReq>) -> Json<ConsensusRes> {
    Json(match payload {
        ConsensusReq::Login { email, password } => user::user_login(&state, email, password).await,
        ConsensusReq::ReqToken { instance, user_id, signature } => user::user_request_token(&state, instance, user_id, signature).await,
        ConsensusReq::ReqUserKey { user_id } => server::server_request_user_key(&state, user_id).await,
        ConsensusReq::Register { username, email, password } => user::user_register(&state, username, email, password).await,
        ConsensusReq::ReqUserInfo { token } => user::user_request_user_info(&state, token).await,
    })
}