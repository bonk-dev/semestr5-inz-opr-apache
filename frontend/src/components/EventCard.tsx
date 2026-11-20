import type { SecurityEvent } from "../models/types";
import { formatDate, formatDuration, isSafe, verdictLabel } from "../utils/format";
import { Field } from "./Field";

interface EventCardProps {
  event: SecurityEvent;
}

export function EventCard({ event }: EventCardProps) {
  const { request: req, classification: c } = event;
  const line = req.requestLine;
  const res = req.response;

  return (
    <article className={`event ${isSafe(c) ? "safe" : "unsafe"}`}>
      <header>
        <strong>{verdictLabel(c)}</strong>
        <span>wynik: {c.score}</span>
        <span className="id">#{event.id}</span>
      </header>

      <div className="columns">
        <section>
          <h3>Zdarzenie</h3>
          <dl>
            <Field label="ID" value={event.id} />
            <Field label="Data klasyfikacji" value={formatDate(event.classifiedAt)} />
            <Field label="Źródło" value={event.source} />
          </dl>
        </section>

        <section>
          <h3>Werdykt</h3>
          <dl>
            <Field label="Werdykt" value={verdictLabel(c)} />
            <Field label="Wynik" value={c.score} />
            <Field label="Powód" value={c.reason} />
            <Field label="ID reguły" value={c.ruleId} />
          </dl>
        </section>

        <section>
          <h3>Żądanie</h3>
          <dl>
            <Field label="IP klienta" value={req.clientIp} />
            <Field label="Czas żądania" value={formatDate(req.timestamp)} />
            <Field label="Linia żądania" value={<code>{line.raw}</code>} />
            <Field label="Rodzaj" value={line.kind} />
            <Field label="Metoda" value={line.method} />
            <Field label="Ścieżka" value={line.path} />
            <Field label="Query" value={line.query} />
            <Field label="Protokół" value={line.protocol} />
            <Field label="Referer" value={req.referer} />
            <Field label="User-Agent" value={req.userAgent} />
            <Field label="Host" value={req.host} />
            <Field label="Protokół TLS" value={req.tlsProtocol} />
            <Field label="Unique ID" value={req.uniqueId} />
          </dl>
        </section>

        {res && (
          <section>
            <h3>Odpowiedź serwera</h3>
            <dl>
              <Field label="Status" value={res.status} />
              <Field label="Wysłane bajty" value={res.bytesSent} />
              <Field label="Rozmiar treści" value={res.bodyBytes} />
              <Field label="Czas odpowiedzi" value={formatDuration(res.duration)} />
            </dl>
          </section>
        )}
      </div>
    </article>
  );
}
