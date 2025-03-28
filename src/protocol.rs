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
    InstReqUserKey { user_id: String },
    /// User requests their online user information from sign-on instance
    ReqUserData { token: String },
    /// User creates server
    CreateServer { token: String, server_name: String},
    /// Join a server
    JoinServer { token: String, server_id: String},
    /// Get data about a server the user is a member of
    ReqServerData {token: String, server_id: String},
    /// Request server structure
    ReqServerStructure {token: String, server_id: String},
    /// Request user data synchronization
    SyncUserData { token: String, data: SyncedUserData},
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
    /// User has joined a server, gets the server id
    ServerJoin(String),
    /// User has requested data about a server they are part of
    ServerData(ServerData),
    /// User has requested the server structure
    ServerStructure(ServerStructure),
    /// User has requested user data synchronization and gets the synced data back
    SyncedUserData(SyncedUserData),
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
}

/// Struct for coarse server information
#[derive(Clone, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct ServerData {
    pub name: String,
    pub instance: String,
    pub id: String,
}

/// Struct for server information loaded on server opening
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ServerStructure {
    pub channels: Vec<ChannelList>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub enum ChannelList {
    Channel(Channel),
    ChannelCategory(Vec<Channel>)
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Channel {
    pub name: String,
    pub id: String,
}

/// Struct for all user data that is synced over the sign-on instance
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct SyncedUserData {
    pub last_synced: String,
    pub display_name: String,
    pub status: String,
    pub pronouns: String,
    pub bio: String,
    pub servers: Vec<ServerData>,
}

/// Enum for all consensus protocol errors
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ConsensusError {
    Rejected,
    NotFound,
    TokenExpired,
    Incorrect,
    EmailInUse,
    NotAuthorised,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusError::Rejected => write!(f, "Rejected"),
            ConsensusError::NotFound => write!(f, "NotFound"),
            ConsensusError::TokenExpired => write!(f, "TokenExpired"),
            ConsensusError::Incorrect => write!(f, "Incorrect"),
            ConsensusError::EmailInUse => write!(f, "EmailInUse"),
            ConsensusError::NotAuthorised => write!(f, "NotAuthorised"),
        }
    }
}
