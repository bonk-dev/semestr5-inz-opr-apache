import { useCallback, useEffect,useState } from "react";
import axios from "axios";
import { fetchEvents } from "../api/api";
import { PAGE_SIZE } from "../constants";
import type { SecurityEvent } from "../models/types";

function getErrorMessage(e: unknown){
    if(axios.isAxiosError(e)) {
        if (e.response) return `Błąd API: ${e.response.status} ${e.response.statusText}`;
        if (e.code === "ECONNABORTED") return "Przekroczono czas oczekiwania na API";
        return "Brak połączenia z API";
    }
    return e instanceof Error ? e.message : "Nie udało się pobrać zdarzeń";
}

export function useEvents() {
    const [page,setPage] = useState(0);
    const [events, setEvents] = useState<SecurityEvent[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [reloadKey,setReloadKey] = useState(0);

    useEffect(() => {
        const controller = new AbortController();
        const load = async () => {
            setLoading(true);
            setError(null);

            try{
                const data = await fetchEvents(page,controller.signal);
                setEvents(data.items);
                setTotal(data.total);
            } catch(e){
                if (axios.isCancel(e)) return;
                setError(getErrorMessage(e));
            }finally {
                if(!controller.signal.aborted) setLoading(false);
            }
        };

        load();

        return () => {
            controller.abort();
        };
    }, [page,reloadKey]);

    const nextPage = useCallback(() => setPage((p) => p+1),[]);
    const prevPage = useCallback(() => setPage((p) =>Math.max(0,p-1)),[]);
    const retry = useCallback(()=> setReloadKey((k) => k+1),[]);

    return {
        events,
        total,
        page,
        totalPages: Math.ceil(total / PAGE_SIZE),
        loading,
        error,
        hasPrev: page > 0,
        hasNext: (page + 1) * PAGE_SIZE < total,
        nextPage,
        prevPage,
        retry,
    };
}
