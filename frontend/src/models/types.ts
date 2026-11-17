export interface RequestLine{
    kind: string;
    raw: string;
    method: string | null;
    path: string | null;
    query: string | null;
    protocol: string| null;
}

export interface RequestData {
    clientIp: string;
    timestamp: string;
    requestLine: RequestLine;
    referer: string | null;
    userAgent: string | null;
    host: string | null;
    tlsProtocol: string | null;
    uniqueId: string | null;
    response: unknown | null;
}

export interface Verdict {
    isSafe: boolean;
    score: number;
    reason: string;
    ruleId: string;
}

export interface SecurityEvent {
    id: string;
    classifiedAt: string;
    source: string;
    request: RequestData;
    verdict: Verdict;
}