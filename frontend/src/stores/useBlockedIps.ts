import { useCallback, useEffect,useState } from "react";
import axios from "axios";
import { fetchBlockedIPs } from "../api/api";
import type { BlockedIp } from "../models/blockips";

export function useBlockedIps() {
    const [items, setItems] = useState<BlockedIp[]>([]);
    const [loading, setLoading] = useState(false);
    const[error,setError] = useState<string | null>(null);
    const [reloadKey, setReloadKey] = useState(0);

    useEffect(() => {
        const controller = new AbortController();
        const load = async () => {
            setLoading(true);
            setError(null);

            try{
                const data = await fetchBlockedIPs(controller.signal);
                setItems(data);
            } catch(e){
                if(axios.isCancel(e)) return;
                setError(axios.isAxiosError(e) && e.response
                    ? `Błąd API: ${e.response.status} ${e.response.statusText}` :
                    "Nie udało się pobrać listy zablokowanych adresów IP");
            } finally{
                if(!controller.signal.aborted) setLoading(false);
            }
        };

        load();

        return () => controller.abort();
    },[reloadKey]);

    const retry = useCallback(() => setReloadKey((k) => k+1), []);
    return { items,loading,error,retry };
}