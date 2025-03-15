/// Enum for all consensus protocol requests
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ConsensusReq {
    /// User login request
    Login { email: String, password: String },
    /// User registration request
    Register {
        username: String,
        email: String,
        password: String,
    },
    /// User token request
    ReqToken {
        instance: String,
        user_id: String,
        signature: String,
    },
    /// Instance requests user public key from another instance
    ReqUserKey { user_id: String },
    /// User requests their online user information from sign-on instance
    ReqUserInfo { token: String },
}

/// Enum for all consensus protocol responses
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ConsensusRes {
    Error(ConsensusError),
    /// Login response with (instance, id, username, email, authkey_priv)
    Login(String, String, String, String, String),
    /// Token response, Token request may be denied -> Error
    Token(ConsensusToken),
    /// User key response, a requested users public key
    UserKey(String),
    /// online user information response
    UserInfo(ConsensusUserInfo),
}

/// Struct for consensus auth token
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ConsensusToken {
    pub token: String,
    pub valid_until: String,
}

/// Struct for consensus online user information
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ConsensusUserInfo {
    pub token: String,
    pub valid_until: String,
}

/// Enum for all consensus protocol errors
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ConsensusError {
    Rejected,
    NotFound,
    TokenExpired,
    Incorrect,
    EmailInUse,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusError::Rejected => write!(f, "Rejected"),
            ConsensusError::NotFound => write!(f, "NotFound"),
            ConsensusError::TokenExpired => write!(f, "TokenExpired"),
            ConsensusError::Incorrect => write!(f, "Incorrect"),
            ConsensusError::EmailInUse => write!(f, "EmailInUse"),
        }
    }
}
