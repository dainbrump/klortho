use super::host_record::HostRecord;
use super::ssh_config::{ClientConfiguration, CommentNode, FileNode, HostNode, Node, NodeClass};
use chrono::{DateTime, Utc};
use std::fs;
use std::io;
use std::path::Path;

fn read_file(filepath: &str) -> Result<String, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(filepath)?;
    Ok(contents)
}

// TODO Implement the write_file function
/* fn write_file(filepath: &str, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(filepath, contents)?;
    Ok(())
} */

// Returns the created and modified timestamps for the file at `path` as timestamp strings.
//
// Loads the metadata for the file at `path` specifically fetching the created and modified dates
// and times. Converts those to DateTime<Utc> objects and then to RFC3339 strings. Returns the
// created and modified timestamps as a tuple of strings.
fn file_metadata(path: &Path) -> io::Result<(String, String)> {
    let metadata = fs::metadata(path)?;
    let created: DateTime<Utc> = metadata.created()?.into();
    let modified: DateTime<Utc> = metadata.modified()?.into();
    Ok((created.to_rfc3339(), modified.to_rfc3339()))
}

// Trims blank lines from the supplied `contents` string.
fn trim_lines(contents: &str) -> String {
    let mut trimmed_contents: String = String::new();
    for line in contents.lines() {
        let line = line.trim();
        if !line.is_empty() {
            let formatted = format!("{}\n", line);
            trimmed_contents.push_str(formatted.as_str());
        }
    }
    trimmed_contents
}

// Chunks the contents of the ssh configuration file grouped into  'Host', 'Include', or root-level
// comment blocks. Comments within 'Host' blocks are considered as parts of the 'Host' block.
fn contents_to_chunks(contents: &str) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    let mut stanza: Vec<String> = Vec::new();
    let mut in_comment_block = false;
    let mut finished_host_block = true;
    let lines: Vec<&str> = contents.lines().collect();
    let last_line = lines.len() - 1;

    for line_num in (0..=last_line).rev() {
        let line = lines[line_num];
        if line.starts_with("Host ") {
            // We've reached the start of the Host stanza. Everything that came "before" is part of
            // this stanza. To complete this stanza, we first need to add this line to the chunk.
            stanza.push(line.to_string());
            // Since we started the chunk by reading the file backward, we need to reverse the lines
            // we chunked to get the correct order of the stanza and then join them into a single
            // string.
            stanza.reverse();
            let stanza_string = stanza.join("\n").to_string();
            // Next, we need to push the new string (the stanza) into the chunks vector.
            chunks.push(stanza_string);
            // Finally, reset the chunk to an empty vector to start the next stanza.
            stanza = Vec::new();
            finished_host_block = true;
        } else if line.starts_with("Include ") {
            if !finished_host_block || in_comment_block {
                stanza.reverse();
                let stanza_string = stanza.join("\n").to_string();
                chunks.push(stanza_string);
                stanza = Vec::new();
                in_comment_block = false;
                finished_host_block = true;
            }
            stanza.push(line.to_string());
            stanza.reverse();
            let stanza_string = stanza.join("\n").to_string();
            chunks.push(stanza_string);
            stanza = Vec::new();
        } else if line.starts_with("#") && finished_host_block {
            // We're starting a comment block
            if !in_comment_block {
                in_comment_block = true;
            }
            stanza.push(line.to_string());
        } else {
            if in_comment_block {
                in_comment_block = false;
                stanza.reverse();
                let stanza_string = stanza.join("\n").to_string();
                chunks.push(stanza_string);
                stanza = Vec::new();
            }
            if finished_host_block {
                finished_host_block = false;
            }
            stanza.push(line.to_string());
        }
    }

    if !stanza.is_empty() {
        // If there are any lines left in the stanza, we need to add them to the chunks.
        stanza.reverse();
        let stanza_string = stanza.join("\n").to_string();
        chunks.push(stanza_string);
    }

    // Reverse the collected stanzas so that the chunked "file" is in the original order.
    chunks.reverse();
    chunks
}

// Loads the file at `filepath`, trims empty lines and returns the contents as a vector of chunks
// grouped by 'Host' keyword, 'Include' directive, or comment.
fn chunk_file(filepath: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let contents = read_file(&filepath)?;
    let trimmed_contents = trim_lines(&contents);
    let chunks = contents_to_chunks(&trimmed_contents);
    Ok(chunks)
}

// Processes a chunk of the SSH configuration file as a `Host` record. Returns a `HostNode`.
fn to_host_node(chunk: &str) -> HostNode {
    let mut host_record = HostRecord::new();
    let mut host_record_comments: Vec<String> = Vec::new();
    let mut comments: Option<String> = None;
    for line in chunk.lines() {
        // Need to add conditional check for Host record level comments
        if line.starts_with("#") {
            host_record_comments.push(line.to_string().replace("# ", ""));
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (key, value) = (parts[0], parts[1..].join(" ").to_string());
        host_record.set_property(key, &value);
    }
    if host_record_comments.len() > 0 {
        comments = Some(host_record_comments.join("\n"));
    }
    HostNode {
        node_type: NodeClass::Host,
        comments,
        record: host_record,
    }
}

// Processes a chunk of the SSH configuration file as a comment. Returns a `CommentNode`.
fn to_comment_node(chunk: &str) -> CommentNode {
    let comment = chunk.trim().to_string().replace("# ", "");
    CommentNode {
        node_type: NodeClass::Comment,
        comment,
    }
}

fn to_file_node(path_str: &str, node_type: NodeClass) -> FileNode {
    let full_path = shellexpand::tilde(&path_str).to_string();
    let path = Path::new(&full_path);
    let filename = path.file_name().unwrap().to_str().unwrap().to_string();
    let filepath = path.parent().unwrap().display().to_string();
    let (created, modified) = file_metadata(path).unwrap();
    let chunks = chunk_file(&full_path).unwrap();
    let nodes = process_chunks(&chunks).unwrap();
    FileNode {
        node_type,
        filename,
        filepath,
        created: Some(created.to_string()),
        updated: Some(modified.to_string()),
        nodes,
    }
}

fn process_chunks(chunks: &Vec<String>) -> Result<Vec<Node>, Box<dyn std::error::Error>> {
    let mut nodes: Vec<Node> = Vec::new();
    for chunk in chunks {
        let first_line = chunk.lines().next().unwrap();
        if first_line.starts_with("Host ") {
            let node: Node = Node::Host(to_host_node(&chunk));
            nodes.push(node);
        }
        if first_line.starts_with("#") {
            let node: Node = Node::Comment(to_comment_node(&chunk));
            nodes.push(node);
        }
        if first_line.starts_with("Include ") {
            let inc_directive: Vec<&str> = chunk.split_whitespace().collect();
            let inc_path = inc_directive[1..].join(" ");
            let node: Node = Node::File(to_file_node(&inc_path, NodeClass::Include));
            nodes.push(node);
        }
    }
    Ok(nodes)
}

pub fn load_tree_from_config_file(
    cfg: &str,
) -> Result<ClientConfiguration, Box<dyn std::error::Error>> {
    let mut nodes: Vec<Node> = Vec::new();
    let root_node = Node::File(to_file_node(&cfg, NodeClass::Root));
    nodes.push(root_node);
    Ok(ClientConfiguration { nodes })
}
