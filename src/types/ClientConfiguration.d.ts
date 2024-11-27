import { HostRecord } from "./HostRecord";

export type Nodes = (FileNode | HostNode | CommentNode)[];

export type HostNode ={
  node_type: 'host';
  comments?: string;
  record: HostRecord;
}

export type CommentNode = {
  node_type: 'comment';
  comment: string;
}

export type FileNode = {
  node_type: 'root' | 'include';
  filename?: string;
  filepath?: string;
  created?: string;
  updated?: string;
  nodes: Nodes;
}

export type ClientConfiguration = {
  nodes: Nodes;
};