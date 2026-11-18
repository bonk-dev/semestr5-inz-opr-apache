import { useState } from "react";
import EventsPage from "./pages/EventsPage";
import BlockedIpsPage from "./pages/BlockedIpsPage";

type Tab = "events" | "blocked"; 

export default function App() {
  const [tab, setTab] = useState<Tab>("events");

  return(
    <>
      <nav className="app-nav">
        <button onClick={() => setTab("events")} aria-pressed={tab === "events"}>
          Logi
        </button>
        <button onClick={() => setTab("blocked")} aria-pressed={tab === "blocked"}>
          Zablokowane IP
        </button>
      </nav>

      {tab === "events" ? <EventsPage/> : <BlockedIpsPage/>}
    </>
  );
}
