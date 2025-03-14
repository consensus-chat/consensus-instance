/// Enum for all consensus protocol client requests
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ConsensusReq {
    Login {email: String, password: String},
}

/// Enum for all consensus protocol server responses
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ConsensusRes {
    /// Login response, either success with authkey or failure with error
    Login {res: Result<String, String>},
}