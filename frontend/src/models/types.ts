export interface RequestLine{
    kind: string;
    raw: string;
    method: string | null;
    path: string | null;
    query: string | null;
    protocol: string| null;
}

export interface ResponseInfo {
    status: number;
    bytesSent: number;
    bodyBytes: number;
    duration: string;
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
    response: ResponseInfo | null;
}

export interface Classification {
    verdict: string;
    score: number;
    reason: string;
    ruleId: number | null;
}

export interface SecurityEvent {
    id: number;
    classifiedAt: string;
    source: string;
    request: RequestData;
    classification: Classification;
}

export interface EventsResponse {
    items: SecurityEvent[];
    total: number;
}
