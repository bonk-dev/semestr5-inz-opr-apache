import type { Log } from "../data/data";

export default function LogTable({ logs }: { logs: Log[] }) {
    return(
        <table>
            <thead>
                <tr>
                <th>Data</th>
                <th>Adres IP</th>
                <th>Metoda</th>
                <th>Sciezka</th>
                <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {logs.map((log)=>(
                    <tr key={log.id}>
                        <td>{log.date}</td>
                        <td>{log.ip}</td>
                        <td>{log.method}</td>
                        <td>{log.path}</td>
                        <td>{log.status}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}