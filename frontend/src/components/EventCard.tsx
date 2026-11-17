import type { SecurityEvent } from "../models/types";
import { dash,formatDate } from "../utils/format";
import { Field } from "./Field";

interface EventCardProps {
    event: SecurityEvent;
}

export function EventCard({event}: EventCardProps){
    const {request: req, verdict } = event;
    const line = req.requestLine;

    return (
        <article className={`event ${verdict.isSafe ? "safe" : "dangerous"}`}>
            <header>
                <strong>{verdict.isSafe ? "Bezpieczny" : "Niebezpieczny"}</strong>
                <span>wynik: {verdict.score}</span>
                <span className="id">{event.id}</span>
            </header>

            <div className="columns">
                <section>
                    <h3>Zdarzenia</h3>
                    <dl>
                        <Field label="ID" value={event.id}/>
                        <Field label="Data klasyfikacji" value={formatDate(event.classifiedAt)}/>
                        <Field label="Źródło" value={event.source}/>
                    </dl>
                </section>

                <section>
                    <h3>Żądanie</h3>
                    <dl>
                        <Field label="IP klienta" value={req.clientIp}/>
                        <Field label="Czas żądania" value={formatDate(req.timestamp)}/>
                        <Field label="Linia żądania" value={<code>{line.raw}</code>}/>
                        <Field label="Rodzaj" value={line.kind}/>
                        <Field label="Metoda" value={dash(line.method)}/>
                        <Field label="Ścieżka" value={dash(line.path)}/>
                        <Field label="Query" value={dash(line.query)}/>
                        <Field label="Protokół" value={dash(line.protocol)}/>
                        <Field label="Referer" value={dash(req.referer)}/>
                        <Field label="User-Agent" value={dash(req.userAgent)}/>
                        <Field label="Host" value={dash(req.host)}/>
                        <Field label="Protokół TLS" value={dash(req.tlsProtocol)}/>
                        <Field label="Unique ID" value={dash(req.uniqueId)}/>
                        <Field label="Odpowiedź" value={req.response == null ? null : (
                            <pre>{JSON.stringify(req.response,null,2)}</pre>
                        )}/>
                    </dl>
                </section>
            </div>
        </article>
    );
}