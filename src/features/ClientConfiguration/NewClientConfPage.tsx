import { useState } from 'react';
import { SSHHostRecord } from '@klortho/types';
import HostEntry from './HostEntry/HostEntry';
import OpenSshConfigCard from './components/OpenSshConfigCard';
import CreateSshConfigCard from './components/CreateSshConfigCard';

function NewClientConfPage () {
  const [hosts, setHosts] = useState<{[key: string]: SSHHostRecord[]}>({});
  
  const [selectedFile, setSelectedFile] = useState<string | null>(null);

  const loadConfig = async (loaded: {filename: string, configdata:{[key: string]: SSHHostRecord[]}}) => {
    setSelectedFile(loaded.filename);
    setHosts(loaded.configdata);
  }

  return (
    <div className="klortho-feature-page">
      {!selectedFile ? (
        <div className="grid grid-cols-2 gap-4 py-4">
          <OpenSshConfigCard onLoadConfig={loadConfig} />
          <CreateSshConfigCard onLoadConfig={loadConfig} />
        </div>
      ) : Object.keys(hosts).map((group_name, idx) => (
        <div className="flex flex-col" key={idx}>
          <h2>{group_name}</h2>
          <div className="grid grid-cols-3 gap-4 py-4" key={idx}>
            {hosts[group_name].map((host, index) => (
              <HostEntry key={index} record={host} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export default NewClientConfPage;