import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { ClientConfiguration, FileNode, HostNode } from "@klortho/types";
import { Card, CardContent, CardHeader, CardTitle } from "@klortho/components/ui/card";
import { Button } from "@klortho/components/ui/button";
import { useToast } from "@klortho/hooks/use-toast";

interface SshConfigCardProps {
  onLoadConfig: (loaded: {
    filename: string,
    configdata: ClientConfiguration
  }) => void;
}

function CreateSshConfigCard({onLoadConfig}: SshConfigCardProps) {
  const { toast } = useToast()

  const selectFile = async () => {
    const file = await save({ defaultPath: 'config' });
    if (file) {
      const empty_host: HostNode = {node_type: 'host', record: {host: '*'}};
      const root_file: FileNode = {node_type: 'root', nodes: []};
      root_file.nodes.push(empty_host);
      const root_nodes = [];
      root_nodes.push(root_file);
      const initial_config: ClientConfiguration = {nodes: root_nodes};
      const result: string = await invoke('save_client_config', {json: JSON.stringify(initial_config), filepath: file });

      if (result.startsWith("{")) {
        const loaded_hosts: ClientConfiguration = JSON.parse(result);
        onLoadConfig({filename: file, configdata: loaded_hosts});
      } else {
        toast({ variant: "destructive", title: "Uh oh!", description: result})
        console.info(result);
      }
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create a new configuration</CardTitle>
      </CardHeader>
      <CardContent>
        <Button onClick={selectFile}>Create File</Button>
      </CardContent>
    </Card>
  );
}

export default CreateSshConfigCard;