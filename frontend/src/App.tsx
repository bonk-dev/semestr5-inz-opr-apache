import LogTable from "./logs/LogTable";
import { logs } from "./data/data";

export default function App() {
  return (
    <div style={{ padding: 24 }}>
      <h1>Logi Apache</h1>
      <LogTable logs={logs} />
    </div>
  );
}
