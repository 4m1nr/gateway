import { api, type ConfigDoc, type ConfigResponse } from "./api";

/**
 * Reading and writing gateway.toml.
 *
 * A save replaces ONE section. Sending the whole document would mean two open
 * tabs overwriting each other's unrelated edits, and a bug on one page
 * corrupting a section it never touched.
 */

export async function readConfig(): Promise<ConfigResponse> {
  return api.get<ConfigResponse>("/api/config");
}

export async function writeSection(section: string, value: unknown): Promise<void> {
  await api.put(`/api/config/${encodeURIComponent(section)}`, value);
}

/** Read a section, with a default for a config that does not define it yet. */
export function section<T>(doc: ConfigDoc | null, name: string, fallback: T): T {
  if (!doc) return fallback;
  const value = doc[name];
  return value === undefined || value === null ? fallback : (value as T);
}

/** Split a comma or newline separated list into trimmed entries. */
export function parseList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/** Render a list for a textarea, one per line. */
export function formatList(items: string[] | undefined): string {
  return (items ?? []).join("\n");
}
