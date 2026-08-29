/** Human-readable byte counts. */
export function bytes(n: number | undefined | null): string {
  if (!n || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  const value = n / 1024 ** i;
  return `${i === 0 ? value : value.toFixed(1)} ${units[i]}`;
}

/** Coarse duration: the question is "how long", never "exactly how long". */
export function duration(sec: number | undefined | null): string {
  if (!sec || sec <= 0) return "0m";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

/** A count with thousands separators, for the killswitch drop counter. */
export function count(n: number | undefined | null): string {
  return (n ?? 0).toLocaleString();
}
