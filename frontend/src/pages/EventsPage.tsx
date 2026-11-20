import { EventsTable } from "../components/EventTable";
import { Pagination } from "../components/Pagination";
import { useEvents } from "../stores/useEvents";

export default function EventsPage() {
    const { events,page,totalPages,loading, error, hasPrev,hasNext, nextPage,prevPage,retry } = useEvents();

    const pager = (
        <Pagination
          page={page}
          totalPages={totalPages}
          hasPrev={hasPrev}
          hasNext={hasNext}
          disabled={loading}
          onPrev={prevPage}
          onNext={nextPage}
        />
    );

    return (
        <main className="events-view">
            <h1>Zdarzenia bezpieczeństwa</h1>
            {pager}

            {loading && <p role="status">Ładowanie...</p>}
            {error && (
                <p role="alert">
                    {error} <button onClick={retry}>Spróbuj ponownie</button>
                </p>
            )}
            {!loading && !error && events.length === 0 && <p>Brak zdarzeń na tej stronie.</p>}
            {!loading && !error && events.length > 0 && <EventsTable events={events} />}

            {pager}
        </main>
    );
}
