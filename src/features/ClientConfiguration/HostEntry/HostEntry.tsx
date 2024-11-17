import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@klortho/components/ui/card";
import { SSHHostRecord } from "@klortho/types";

function HostEntry({ record }: {record:SSHHostRecord}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <span>Host: {record.Host}</span>
          <CardDescription>HostName: {record.HostName}</CardDescription>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p>User: {record.User}</p>
        <p>ProxyCommand: {record.ProxyCommand}</p>
        <p>RemoteCommand: {record.RemoteCommand}</p>
        <p>Tunnel: {record.Tunnel}</p>
        {/* <code>{JSON.stringify(record)}</code> */}
      </CardContent>
    </Card>
  );
}

export default HostEntry;
