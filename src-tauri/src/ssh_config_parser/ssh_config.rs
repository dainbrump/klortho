use super::host_record::HostRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Represents the different of nodes in the parsed SSH configuration JSON.
///
/// The `Root` class is the root node of the configuration.
/// The `Include` class represents an `Include` directive in the configuration.
/// The `Host` class represents a `Host` directive in the configuration.
/// The `Comment` class represents a comment in the configuration.
pub enum NodeClass {
    Root,
    Include,
    Host,
    Comment,
}

// #[derive(Debug, Clone, Deserialize, Serialize)]
// #[serde(rename_all = "snake_case")]
// Defines a node type in the parsed SSH configuration JSON.
//
// The `class` field is required and must be one of the values in the `NodeClass` enum.
// The `comment` field is optional and only required for `NodeClass::Comment`.
/* pub struct NodeType {
    pub node_type: NodeClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
} */

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Defines a host node in the parsed SSH configuration JSON.
///
/// The `record` field is required and must be a `HostRecord` struct.
pub struct HostNode {
    pub node_type: NodeClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
    pub record: HostRecord,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Defines a comment node in the parsed SSH configuration JSON.
///
/// The `comment` field is required and must be a string.
pub struct CommentNode {
    pub node_type: NodeClass,
    pub comment: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Defines a file node in the parsed SSH configuration JSON.
/// A FileNode may be have a `class` of `Root` or `Include`. The ClientConfiguration struct may only
/// have one `Root` node. Any other FileNodes must have a `class` of `Include` and must be nested in
/// the `nodes` vector of the `Root` node or another `Include` node.
///
/// The `filename` field is required and must be a string.
/// The `filepath` field is required and must be a string.
/// The `nodes` field is required and must be a vector of `Node` structs.
pub struct FileNode {
    pub node_type: NodeClass,
    pub filename: String,
    pub filepath: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
/// Represents a node class in the parsed SSH configuration JSON.
pub enum Node {
    File(FileNode),
    Host(HostNode),
    Comment(CommentNode),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Defines the client configuration for the parsed SSH configuration JSON.
///
/// The `meta` field is required and must be a `Meta` struct.
/// The `nodes` field is required and must be a vector of `Node` structs.
pub struct ClientConfiguration {
    pub nodes: Vec<Node>,
}
