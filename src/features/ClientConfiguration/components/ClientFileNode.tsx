import { Nodes, FileNode, CommentNode, HostNode } from "@klortho/types";
import ClientCommentNode from "./ClientCommentNode";
import ClientHostNode from "./ClientHostNode";

function ClientFileNode({ nodes }: { nodes: Nodes }) {

  const node_selection = (node: FileNode | CommentNode | HostNode, idx: number) => {
    switch (node.node_type) {
      case 'include':
      case 'root':
        return (
          <div key={idx} className="min-h-[100vh] flex-1 md:min-h-min"> 
            <h2>{node.node_type === 'root' ? 'Root Configuration File' : 'Include Configuration File'}</h2>
            <span>{node.filepath}/{node.filename}</span>
            {node.nodes.map((childNode, childIdx) => (
              node_selection(childNode, childIdx)
            ))}
          </div>
        );
      case 'host':
        return <ClientHostNode key={idx} node={node} />;
      case 'comment':
        return <ClientCommentNode key={idx} node={node} />;
    }
  };

  return (
    <div className="min-h-[100vh] flex-1 md:min-h-min">
      <div className="grid auto-rows-min gap-4 md:grid-cols-3">
        {nodes.map((node, idx) => (
          node_selection(node, idx)
        ))}
      </div>
    </div>
  );
}

export default ClientFileNode;