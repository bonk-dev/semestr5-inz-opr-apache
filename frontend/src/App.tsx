import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import "./App.css";

type EventItem = { id: number; eventTimeUtc: string; detectedAtUtc: string; severity: string; method: string; url: string; clientIp: string };
type EventDetail = EventItem & { rawLogLine: string; requestJson: string; detectionJson: string };

export default function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [events, setEvents] = useState<EventItem[]>([]);
  const [detail, setDetail] = useState<EventDetail | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => { void fetch("/api/auth/me", { credentials: "same-origin" }).then(response => { if (response.ok) setLoggedIn(true); }); }, []);

  async function login(event: FormEvent) {
    event.preventDefault(); setError("");
    const response = await fetch("/api/auth/login", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
    if (!response.ok) { setError("Nieprawidłowe dane logowania"); return; }
    setPassword(""); setLoggedIn(true);
  }

  async function loadEvents() {
    setLoading(true); setError("");
    try { const response = await fetch("/api/anomalies?page=1&pageSize=100", { credentials: "same-origin" }); if (!response.ok) throw new Error("Nie udało się pobrać zdarzeń"); setEvents((await response.json()).items); }
    catch (exception) { setError(exception instanceof Error ? exception.message : "Błąd komunikacji z API"); }
    finally { setLoading(false); }
  }

  useEffect(() => { if (loggedIn) void loadEvents(); }, [loggedIn]);

  async function showDetail(id: number) { const response = await fetch(`/api/anomalies/${id}`, { credentials: "same-origin" }); if (response.ok) setDetail(await response.json()); }
  async function logout() { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); setLoggedIn(false); setDetail(null); }

  if (!loggedIn) return <main className="page"><h1>Schiza</h1><form className="card login" onSubmit={login}><h2>Logowanie administratora</h2><label>Użytkownik<input value={username} onChange={event => setUsername(event.target.value)} /></label><label>Hasło<input type="password" value={password} onChange={event => setPassword(event.target.value)} /></label><button>Zaloguj</button>{error && <p className="error">{error}</p>}</form></main>;

  return (
    <main className="page"><header><h1>Oflagowane zdarzenia Apache</h1><button onClick={() => void logout()}>Wyloguj</button></header>{error && <p className="error">{error}</p>}{loading ? <p>Ładowanie…</p> : events.length === 0 ? <p>Brak zapisanych anomalii.</p> : <table><thead><tr><th>Czas</th><th>Adres</th><th>Żądanie</th><th>Poziom</th><th /></tr></thead><tbody>{events.map(item => <tr key={item.id}><td>{new Date(item.eventTimeUtc).toLocaleString()}</td><td>{item.clientIp}</td><td>{item.method} {item.url}</td><td>{item.severity}</td><td><button onClick={() => void showDetail(item.id)}>Szczegóły</button></td></tr>)}</tbody></table>}{detail && <section className="card detail"><button onClick={() => setDetail(null)}>Zamknij</button><h2>Zdarzenie #{detail.id}</h2><p><strong>{detail.method} {detail.url}</strong> — {detail.severity}</p><p>Wpis Apache: <code>{detail.rawLogLine}</code></p><h3>Dane detekcji i XAI</h3><pre>{JSON.stringify(JSON.parse(detail.detectionJson), null, 2)}</pre><h3>Sparsowane żądanie</h3><pre>{JSON.stringify(JSON.parse(detail.requestJson), null, 2)}</pre></section>}</main>
  );
}
