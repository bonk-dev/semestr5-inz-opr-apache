import type { EventsResponse } from "../models/types";
import {PAGE_SIZE} from "../constants";
import { apiClient } from "./apiClient";
import type { BlockedIp } from "../models/blockips";

export async function fetchEvents(
    page: number,
    signal?: AbortSignal,
): Promise<EventsResponse> {
    const { data } = await apiClient.get<EventsResponse>(
        "/events",
        {
            params: {
                Skip: page * PAGE_SIZE,
                Take: PAGE_SIZE,
            },
            signal,
        }
    );

    return data;
}

type RawBlockedIp = string | { ip: string; reason?: string };

export async function fetchBlockedIPs(signal?: AbortSignal): Promise<BlockedIp[]> {
    const { data } = await apiClient.get<RawBlockedIp[] | { items: RawBlockedIp[] }>(
        "/blocked-ips",
        { signal },
    );

    const raw =Array.isArray(data) ? data : data.items ?? [];

    return raw.map( (r) =>
    typeof r === "string"
      ? { ip: r, reason: null }
      : { ip: r.ip,reason: r.reason ?? null }
    );
}
