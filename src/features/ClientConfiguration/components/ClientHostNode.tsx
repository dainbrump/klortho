import { HostNode, HostRecord } from "@klortho/types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@klortho/components/ui/card";

function ClientHostNode ({node}: {node: HostNode}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{node.record.host}</CardTitle>
        {node.record.host_name && <CardDescription>{node.record.host_name}</CardDescription>}
      </CardHeader>
      <CardContent>
        <ul>
          { Object.keys(node.record).map((param, index) => (
            <li key={index}><strong>{param}</strong>: { String(node.record[param as keyof HostRecord]) }</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export default ClientHostNode;