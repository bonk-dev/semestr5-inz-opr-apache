import { Fragment, useState } from "react";
import type { SecurityEvent } from "../models/types";
import { formatDate,isSafe, verdictLabel } from "../utils/format";
import { EventCard } from "./EventCard";

interface EventsTableProps {
    events: SecurityEvent[];
}

export function EventsTable({events}: EventsTableProps){
    const [expandedId, setExpandedId] = useState<number | null>(null);
    const toggle = (id: number) => setExpandedId((cur) => (cur === id ? null : id));

    return (
        <div className="table-wrapper">
            <table className="events-table">
                <thead>
                    <tr>
                        <th>Data klasyfikacji</th>
                        <th>Czas żądania</th>
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
                        return (
                            <Fragment key={e.id}>
                                <tr className={isSafe(e.classification) ? "safe" : "unsafe"}>
                                    <td>{formatDate(e.classifiedAt)}</td>
                                    <td>{formatDate(e.request.timestamp)}</td>
                                    <td className="cell-ip">{e.request?.clientIp}</td>
                                    <td>
                                        <code>{e.request.requestLine.raw}</code>
                                    </td>
                                    <td>{e.source}</td>
                                    <td className="cell-verdict">{verdictLabel(e.classification)}</td>
                                    <td className="cell-score">
                                        {e.classification.score}
                                    </td>
                                    <td>
                                        <button onClick={() => toggle(e.id)} aria-expanded={open}>
                                            {open ? "Ukryj" : "Szczegóły"}
                                        </button>
                                    </td>
                                </tr>
                                {open && (
                                    <tr className="details">
                                        <td colSpan={8}>
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
