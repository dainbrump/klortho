import { useEffect, useState } from 'react';
import { SSHHostRecord } from '@klortho/types';
import { invoke } from '@tauri-apps/api/core';

function ClientConfigurationPage () {
  const [hosts, setHosts] = useState<{[key: string]: SSHHostRecord[]}>({});

  async function loadConfig() {
    console.info('Loading ssh configuration...');
    const filepath = '~/Projects/dainbrump/ssh-samples/config';
    const host_data: {[key: string]: SSHHostRecord[]} = JSON.parse(await invoke('load_config', { filepath }));
    setHosts(host_data);
  }

  useEffect(() => {
    loadConfig()
  }, []);

  return (
    <div>
      <h1>Client Configuration</h1>
      {Object.keys(hosts).map((group_name, idx) => (
        <div key={idx}>
          <h2>{group_name}</h2>
          <ul>
            {hosts[group_name].map((host, index) => (
              <li key={index}>
                <span>{host?.Host}</span>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <p>Hosts: {JSON.stringify(hosts)}</p>
    </div>
  );
}

export default ClientConfigurationPage;