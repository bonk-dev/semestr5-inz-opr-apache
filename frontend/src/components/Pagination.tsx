interface PaginationProps {
    page: number;
    totalPages: number;
    hasPrev: boolean;
    hasNext: boolean;
    disabled?: boolean;
    onPrev: () => void;
    onNext: () => void;
}

export function Pagination({page,totalPages, hasPrev,hasNext,disabled =false,onPrev,onNext}:PaginationProps) {
    return (
        <nav className="pager" aria-label="Paginacja">
            <button onClick={onPrev} disabled={!hasPrev || disabled}>
                Poprzednia
            </button>
            <span>Strona {page+1} z {Math.max(totalPages,1)}</span>
            <button onClick={onNext} disabled={!hasNext || disabled}>
                Następna
            </button>
        </nav>
    );
}
