import type { ReactNode } from "react";

interface FiledProps {
    label: string;
    value: ReactNode
}

export function Field({label,value}: FiledProps) {
    return (
        <div className="field">
            <dt>{label}</dt>
            <dt>{value}</dt>
        </div>
    );
}