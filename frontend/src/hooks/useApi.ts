import { useCallback, useEffect, useRef, useState } from "react";

/** Generic data-fetching hook with polling support. */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  pollMs?: number,
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const result = await fetcher();
      if (mounted.current) setData(result);
    } catch (e) {
      if (mounted.current) setError((e as Error).message);
    } finally {
      if (mounted.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    mounted.current = true;
    load();
    if (pollMs && pollMs > 0) {
      timer.current = window.setInterval(load, pollMs);
    }
    return () => {
      mounted.current = false;
      if (timer.current) window.clearInterval(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, pollMs]);

  return { data, error, loading, reload: load, setData };
}
