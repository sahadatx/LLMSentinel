import type { ChangeEvent } from "react";

type PageNavigationProps = {
  label: string;
  page: number;
  pageCount: number;
  onPageChange: (page: number) => void;
};

export function PageNavigation({ label, page, pageCount, onPageChange }: PageNavigationProps) {
  if (pageCount <= 1) return null;

  const firstVisiblePage = Math.max(1, Math.min(page - 2, pageCount - 4));
  const pages = Array.from({ length: Math.min(5, pageCount) }, (_, index) => firstVisiblePage + index);

  return (
    <nav className="pagination-controls" aria-label={`${label} pages`}>
      <button type="button" onClick={() => onPageChange(1)} disabled={page === 1} aria-label="First page" title="First page">«</button>
      <button type="button" onClick={() => onPageChange(Math.max(1, page - 1))} disabled={page === 1} aria-label="Previous page" title="Previous page">‹</button>
      {pages.map((pageNumber) => (
        <button
          type="button"
          key={pageNumber}
          className={pageNumber === page ? "current-page" : ""}
          aria-current={pageNumber === page ? "page" : undefined}
          aria-label={`Page ${pageNumber}`}
          onClick={() => onPageChange(pageNumber)}
        >
          {pageNumber}
        </button>
      ))}
      <button type="button" onClick={() => onPageChange(Math.min(pageCount, page + 1))} disabled={page === pageCount} aria-label="Next page" title="Next page">›</button>
      <button type="button" onClick={() => onPageChange(pageCount)} disabled={page === pageCount} aria-label="Last page" title="Last page">»</button>
    </nav>
  );
}

type TableFooterProps = {
  label: string;
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
  pageSizes?: number[];
};

export function TableFooter({
  label,
  total,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizes = [10, 25, 50],
}: TableFooterProps) {
  const pageCount = Math.ceil(total / pageSize);
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);
  const handleSizeChange = (event: ChangeEvent<HTMLSelectElement>) => onPageSizeChange(Number(event.target.value));

  return (
    <div className="pagination table-pagination">
      <span className="pagination-summary" aria-live="polite">
        Showing <strong>{first}–{last}</strong> of <strong>{total.toLocaleString()}</strong> {label}
      </span>
      <label className="page-size">
        <span>Rows per page</span>
        <select value={pageSize} onChange={handleSizeChange} aria-label={`Rows per page for ${label}`}>
          {pageSizes.map((size) => <option key={size} value={size}>{size}</option>)}
        </select>
      </label>
      <PageNavigation label={label} page={page} pageCount={pageCount} onPageChange={onPageChange} />
    </div>
  );
}
