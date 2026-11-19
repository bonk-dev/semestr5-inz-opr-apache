export const dash = (value: string | null | undefined): string =>
    value && value.length > 0 ? value: "-";

export const formatDate = (iso: string): string =>
    new Date(iso).toLocaleString("pl-PL");