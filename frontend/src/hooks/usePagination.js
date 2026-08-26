import { useState, useMemo } from 'react';

/**
 * Client-side pagination over an already-fetched array. For endpoints with
 * no server-side page/size support (false positives, exclusions) — slices
 * in the browser rather than leaving the whole list unpaginated on screen.
 */
export function usePagination(items, pageSize = 15) {
  const [page, setPage] = useState(1);
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  // Clamped inline rather than synced back via a useEffect + setState —
  // avoids rendering one frame with an out-of-range page (and the extra
  // render pass) whenever the underlying list shrinks (filter change, delete).
  const currentPage = Math.min(page, totalPages);

  const pageItems = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, currentPage, pageSize]);

  return {
    page: currentPage,
    totalPages,
    total,
    pageItems,
    goToPrev: () => setPage((p) => Math.max(1, p - 1)),
    goToNext: () => setPage((p) => Math.min(totalPages, p + 1)),
    resetPage: () => setPage(1),
  };
}
