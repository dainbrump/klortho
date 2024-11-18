import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@klortho/components/ui/card";
import { SSHHostRecord } from "@klortho/types";
import { PcCase } from "lucide-react";

function HostEntry({ record }: {record:SSHHostRecord}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <span className="flex items-center"> 
            <PcCase size={24} className="mr-2" />
            {record.Host}
          </span>
          {record.HostName && <CardDescription>HostName: {record.HostName}</CardDescription>}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {record.User && <p>User: {record.User}</p>}
        {record.ProxyCommand && <p>ProxyCommand: {record.ProxyCommand}</p>}
        {record.RemoteCommand && <p>RemoteCommand: {record.RemoteCommand}</p>}
        {record.Tunnel && <p>Tunnel: {record.Tunnel}</p>}
        {/* <code>{JSON.stringify(record)}</code> */}
      </CardContent>
    </Card>
  );
}

export default HostEntry;
