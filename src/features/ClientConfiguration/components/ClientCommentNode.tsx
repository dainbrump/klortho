import { CommentNode } from "@klortho/types";
import { Card, CardContent, CardHeader, CardTitle } from "@klortho/components/ui/card";

function ClientCommentNode ({node}: {node: CommentNode}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Comment</CardTitle>
      </CardHeader>
      <CardContent>
        {node.comment.split('\n').map((line, idx) => (
          <p key={idx}>{line}</p>
        ))}
      </CardContent>
    </Card>
  );
}

export default ClientCommentNode;