import { useEffect, useState } from 'react';
import { SSHHostRecord } from '@klortho/types';
import { invoke } from '@tauri-apps/api/core';
import HostEntry from './HostEntry/HostEntry';

function ClientConfigurationPage () {
  const [hosts, setHosts] = useState<{[key: string]: SSHHostRecord[]}>({});

  async function loadConfig() {
    const filepath = '~/Projects/dainbrump/ssh-samples/config';
    const host_data: {[key: string]: SSHHostRecord[]} = JSON.parse(await invoke('load_config', { filepath }));
    setHosts(host_data);
  }

  useEffect(() => {
    loadConfig()
  }, []);

  return (
    <div className="klortho-feature">
      {Object.keys(hosts).map((group_name, idx) => (
        <div className="flex flex-col" key={idx}>
          <h2>{group_name}</h2>
          <div className="grid grid-cols-3 gap-4 py-4 flex flex-col" key={idx}>
            {hosts[group_name].map((host, index) => (
              <HostEntry key={index} record={host} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export default ClientConfigurationPage;