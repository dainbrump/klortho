import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Card, CardContent, CardHeader, CardTitle } from "@klortho/components/ui/card";
import { Button } from "@klortho/components/ui/button";
import { ClientConfiguration } from "@klortho/types";

interface SshConfigCardProps {
  onLoadConfig: (loaded: {
    filename: string,
    configdata: ClientConfiguration
  }) => void;
}

function OpenSshConfigCard({onLoadConfig}: SshConfigCardProps) {
  const selectFile = async () => {
    const file = await open({ multiple: false, directory: false });
    if (file) {
      const client_config: ClientConfiguration = JSON.parse(await invoke('load_client_config', { filepath: file }));
      console.log(client_config);
      onLoadConfig({filename: file, configdata: client_config});
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