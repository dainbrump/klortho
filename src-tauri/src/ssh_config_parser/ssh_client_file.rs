use host_record::HostRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Node {
    Root(FileNode),
    Include(FileNode),
    Host(HostNode),
    Comment(CommentNode),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostNode {
    pub id: String,
    pub comment: Option<String>,
    pub record: HostRecord,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommentNode {
    pub id: String,
    pub comment: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileNode {
    pub id: String,
    pub comment: Option<String>,
    pub filename: String,
    pub filepath: String,
    pub nodes: Vec<Node>, // Recursive definition using the Node enum
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfiguration {
    pub id: String,
    pub meta: Meta,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Meta {
    pub created: String,
    pub updated: String,
}