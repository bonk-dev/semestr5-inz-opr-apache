import { useBlockedIps } from "../stores/useBlockedIps";

export default function BlockedIpsPage(){
    const { items, loading, error, retry } = useBlockedIps();

    return (
        <main className="blocked-ips-view">
            <h1>Zablokowane adresy IP</h1>

            {loading && <p role="status">Ładownaie...</p>}
            {error && (
                <p role="alert">
                    {error} <button onClick={retry}>Spróbuj ponownie</button>
                </p>
            )}
            {!loading && !error && items.length === 0 && <p>Brak zablokowanych adresów IP.</p>}
            {!loading && !error && items.length > 0 && (
                <table>
                    <thead>
                        <tr>
                            <th>Adres IP</th>
                            <th>Powód</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.map((b) =>(
                            <tr key={b.ip}>
                                <td>{b.ip}</td>
                                <td>{b.reason ?? "-"}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </main>
    );
}