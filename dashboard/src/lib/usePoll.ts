import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api";

/**
 * Poll an endpoint on an interval.
 *
 * Polling pauses while the tab is hidden. The box is a thin client and the
 * status endpoint shells out to nft and systemctl; a forgotten background tab
 * should not keep it busy.
 */
export function usePoll<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
): {
  data: T | null;
  error: string | null;
  loading: boolean;
  refresh: () => Promise<void>;
} {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Held in a ref so changing the fetcher identity between renders does not
  // restart the interval.
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refresh = useCallback(async () => {
    try {
      setData(await fetcherRef.current());
      setError(null);
    } catch (err) {
      // A 401 is handled globally by the API client, which sends the app back
      // to the login screen; surfacing it here too would flash an error first.
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let timer: number | undefined;
    const tick = () => {
      if (!document.hidden) void refresh();
      timer = window.setTimeout(tick, intervalMs);
    };
    void refresh();
    timer = window.setTimeout(tick, intervalMs);

    const onVisible = () => {
      if (!document.hidden) void refresh();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [intervalMs, refresh]);

  return { data, error, loading, refresh };
}
