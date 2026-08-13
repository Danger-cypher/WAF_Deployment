import { ChevronLeft, ChevronRight } from 'lucide-react';

/**
 * The one shared pagination control — pair with usePagination() for
 * client-side lists, or drive `page`/`totalPages`/`total` directly for
 * server-paginated ones. Previously reimplemented independently per page
 * with drifting markup and wording; this is the canonical version.
 */
export default function Pagination({ page, totalPages, total, itemLabel = 'items', onPrev, onNext }) {
  if (totalPages <= 1) return null;

  return (
    <div className="pagination-container">
      <button
        className="pagination-btn"
        disabled={page === 1}
        onClick={onPrev}
      >
        <ChevronLeft size={16} /> Previous
      </button>
      <span className="pagination-info">
        Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
        <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong> ({total} total {itemLabel})
      </span>
      <button
        className="pagination-btn"
        disabled={page >= totalPages}
        onClick={onNext}
      >
        Next <ChevronRight size={16} />
      </button>
    </div>
  );
}
