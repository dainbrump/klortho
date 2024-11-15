import { SSHHostRecord } from "@klortho/types";

const HostEntry = ({ record }: {record:SSHHostRecord}) => {
  return (
    <div>
      <h1>{record.Host}</h1>
      <p>Host Entry content</p>
    </div>
  );
}

export default HostEntry;
