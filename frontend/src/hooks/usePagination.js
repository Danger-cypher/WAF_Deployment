import { useState, useMemo, useEffect } from 'react';

/**
 * Client-side pagination over an already-fetched array. For endpoints with
 * no server-side page/size support (false positives, exclusions) — slices
 * in the browser rather than leaving the whole list unpaginated on screen.
 */
export function usePagination(items, pageSize = 15) {
  const [page, setPage] = useState(1);
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  // Snap back into range when the underlying list shrinks (e.g. a filter
  // change or a delete) and the current page no longer exists.
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const pageItems = useMemo(() => {
    const start = (page - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, page, pageSize]);

  return {
    page,
    totalPages,
    total,
    pageItems,
    goToPrev: () => setPage((p) => Math.max(1, p - 1)),
    goToNext: () => setPage((p) => Math.min(totalPages, p + 1)),
    resetPage: () => setPage(1),
  };
}
