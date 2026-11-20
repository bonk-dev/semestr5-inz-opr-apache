import type { Classification } from "../models/types";

export const formatDate = (iso: string): string =>
    new Date(iso).toLocaleString("pl-PL");

export const isSafe = (c: Classification): boolean =>
  c.verdict.toLowerCase() === "safe";

export const verdictLabel = (c: Classification): string => {
  switch (c.verdict.toLowerCase()) {
    case "safe":
      return "Bezpieczny";
    case "unsafe":
      return "Niebezpieczny";
    default:
      return c.verdict;
  }
};

export function formatDuration(ts: string): string {
  const m = /^(?:(\d+)\.)?(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(ts);
  if (!m) return ts;
  const [, d, h, min, s, frac] = m;
  const seconds = (Number(d ?? 0) * 24 + Number(h)) * 3600 + Number(min) * 60 + Number(s);
  const ms = Math.round((seconds + Number(`0.${frac ?? "0"}`)) * 1000);
  return `${ms} ms`;
}
