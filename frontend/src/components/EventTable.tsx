import { Fragment, useState } from "react";
import type { SecurityEvent } from "../models/types";
import { formatDate } from "../utils/format";
import { EventCard } from "./EventCard";

interface EventsTableProps {
    events: SecurityEvent[];
}

export function EventsTable({events}: EventsTableProps){
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const toggle = (id: string) => setExpandedId((cur) => (cur === id ? null : id));

    return (
        <div className="table-wrapper">
            <table className="events-table">
                <thead>
                    <tr>
                        <th>Data klasyfikacji</th>
                        <th>Ip klienta</th>
                        <th>Żądanie</th>
                        <th>Źródło</th>
                        <th>Werdykt</th>
                        <th>Wynik</th>
                        <th aria-label="Szczegóły"/>
                    </tr>
                </thead>
                <tbody>
                    {events.map((e) => {
                        const open = expandedId === e.id;
                        const isSafe = e.verdict?.isSafe;
                        return (
                            <Fragment key={e.id}>
                                <tr className={isSafe === undefined ? "" : isSafe ? "safe" : "dangerous"}>
                                    <td>{formatDate(e.classifiedAt)}</td>
                                    <td>{e.request?.clientIp}</td>
                                    <td>
                                        <code>{e.request?.requestLine?.raw}</code>
                                    </td>
                                    <td>{e.source}</td>
                                    <td>{isSafe === undefined ? "-" : isSafe ? "Bezpieczny" : "Niebezpieczny"}</td>
                                    <td>{e.verdict?.score ?? "-"}</td>
                                    <td>
                                        <button onClick={() => toggle(e.id)} aria-expanded={open}>
                                            {open ? "Ukryj" : "Szczegóły"}
                                        </button>
                                    </td>
                                </tr>
                                {open && (
                                    <tr className="details">
                                        <td colSpan={7}>
                                            <EventCard event={e}/>
                                        </td>
                                    </tr>
                                )}
                            </Fragment>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}
