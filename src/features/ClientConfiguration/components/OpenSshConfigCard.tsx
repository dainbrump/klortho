import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { SSHHostRecord } from "@klortho/types";
import { Card, CardContent, CardHeader, CardTitle } from "@klortho/components/ui/card";
import { Button } from "@klortho/components/ui/button";

interface SshConfigCardProps {
  onLoadConfig: (loaded: {
    filename: string,
    configdata: {[key: string]: SSHHostRecord[]}
  }) => void;
}

function OpenSshConfigCard({onLoadConfig}: SshConfigCardProps) {
  const selectFile = async () => {
    const file = await open({ multiple: false, directory: false });
    if (file) {
      const loaded_hosts: {[key: string]: SSHHostRecord[]} = JSON.parse(await invoke('load_client_config', { filepath: file }));
      onLoadConfig({filename: file, configdata: loaded_hosts});
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Load an existing configuration</CardTitle>
      </CardHeader>
      <CardContent>
        <Button onClick={selectFile}>Open File</Button>
      </CardContent>
    </Card>
  );
}

export default OpenSshConfigCard;