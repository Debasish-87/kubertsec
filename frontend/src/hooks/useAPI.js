// hooks/useAPI.js — Reusable data fetching hooks
import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * useAPI — generic hook for fetching data with abort, loading, and error state.
 * @param {Function} fetcher - async function(signal) => data
 * @param {any[]} deps - effect dependencies
 * @param {Object} opts - { immediate: bool }
 */
export function useAPI(fetcher, deps = [], opts = {}) {
  const { immediate = true } = opts;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(immediate);
  const [error, setError] = useState(null);
  const abortRef = useRef(null);

  const run = useCallback(async () => {
    if (abortRef.current) abortRef.current.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const result = await fetcher(ac.signal);
      if (!ac.signal.aborted) {
        setData(result);
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err);
      }
    } finally {
      if (!ac.signal.aborted) {
        setLoading(false);
      }
    }
  }, deps); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (immediate) run();
    return () => { if (abortRef.current) abortRef.current.abort(); };
  }, [run, immediate]);

  return { data, loading, error, refetch: run };
}

/**
 * usePolling — like useAPI but re-runs on an interval.
 */
export function usePolling(fetcher, interval = 15000, deps = []) {
  const { data, loading, error, refetch } = useAPI(fetcher, deps);

  useEffect(() => {
    const t = setInterval(refetch, interval);
    return () => clearInterval(t);
  }, [refetch, interval]);

  return { data, loading, error, refetch };
}

/**
 * useAction — wraps an async action with loading/error state.
 */
export function useAction(fn) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const run = useCallback(async (...args) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fn(...args);
      setResult(res);
      return res;
    } catch (err) {
      setError(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [fn]); // eslint-disable-line react-hooks/exhaustive-deps

  return { run, loading, error, result };
}
