type NodeType = {
	/**
	 * Unique identifier using the `short-unique-id` library
	 *
	 * @type {string}
	 */
	id: string;
	class: 'root' | 'include' | 'host' | 'comment';
	comment?: string;
}

type HostEntry = {
	host: string;
	hostname?: string;
	user?: string;
	identityfile?: string;
}

type HostNode = NodeType & {
	class: 'host';
	record: HostEntry;
}

type CommentNode = NodeType & {
	class: 'comment';
	comment: string;
}

type FileNode = NodeType & {
	class: 'include' | 'root';
	filename: string;
	filepath: string;
	nodes: (FileNode | HostNode | CommentNode)[];
}

type ClientConfiguration = {
	/**
	 * Unique identifier using the `short-unique-id` library
	 *
	 * @type {string}
	 */
	id: string;
	meta: {
		created: string;
		updated: string;
	},
	nodes: (FileNode | HostNode | CommentNode)[];
}
