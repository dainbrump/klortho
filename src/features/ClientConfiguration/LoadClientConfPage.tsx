import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { ClientConfiguration } from "@klortho/types";
import { Button } from "@klortho/components/ui/button";
import ClientFileNode from "./components/ClientFileNode";

function LoadClientConfPage () {
  const [config, setConfig] = useState<ClientConfiguration | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);

  const selectFile = async () => {
    const file = await open({ multiple: false, directory: false });
    if (file) {
      const client_config: ClientConfiguration = JSON.parse(await invoke(
        'load_client_config',
        { filepath: file }
      ));
      console.log(client_config);
      setConfig(client_config);
      setSelectedFile(file);
    }
  }

  return (
    <div className="klortho-feature-page">
      <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
        <h1>Load Client Configuration</h1>
        { selectedFile === null && (<Button onClick={selectFile}>Open File</Button>)}
      </header>
      <div className="flex flex-1 flex-col gap-4 p-4">
        { config === null ? (
          <p>
            Load a configuration file by clicking on the "Open File" button about and selecting an 
            ssh client configuration file.
          </p>
        ) : (
          <ClientFileNode nodes={config.nodes} />
        )}
      </div>
    </div>
  );
}

export default LoadClientConfPage;
