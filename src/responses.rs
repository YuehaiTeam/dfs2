use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
#[serde(untagged)]
pub enum ApiResponse {
    Success(ResponseData),
    Error { message: String },
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ResponseData {
    Metadata {
        #[serde(rename = "_dfs_version")]
        dfs_version: String,
        name: String,
        data: Value
    },
    Challenge {
        challenge: String,
        data: String,
        sid: String,
    },
    Session {
        tries: Vec<String>,
        sid: String,
    },
    Cdn {
        url: String,
    },
    Empty,
}

impl ApiResponse {
    pub fn success(data: ResponseData) -> Self {
        Self::Success(data)
    }

    pub fn error(message: String) -> Self {
        Self::Error { message }
    }
}
