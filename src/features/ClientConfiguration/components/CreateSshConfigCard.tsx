import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { SSHHostRecord } from "@klortho/types";
import { Card, CardContent, CardHeader, CardTitle } from "@klortho/components/ui/card";
import { Button } from "@klortho/components/ui/button";
import { useToast } from "@klortho/hooks/use-toast";

interface SshConfigCardProps {
  onLoadConfig: (loaded: {
    filename: string,
    configdata: {[key: string]: SSHHostRecord[]}
  }) => void;
}

function CreateSshConfigCard({onLoadConfig}: SshConfigCardProps) {
  const { toast } = useToast()

  const selectFile = async () => {
    const file = await save({ defaultPath: 'config' });
    if (file) {
      const initial_config: {[key: string]: SSHHostRecord[]} = {"Default": [{Host: "*", User: "default"}]};
      const result: string = await invoke('save_client_config', {json: JSON.stringify(initial_config), filepath: file });
      if (result.startsWith("{") || result.startsWith("[")) {
        const loaded_hosts: {[key: string]: SSHHostRecord[]} = JSON.parse(result);
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