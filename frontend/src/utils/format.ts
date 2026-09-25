const LOCALE = "vi-VN";

const dateTimeFormat = new Intl.DateTimeFormat(LOCALE, {
  dateStyle: "medium",
  timeStyle: "short",
});
const relativeFormat = new Intl.RelativeTimeFormat(LOCALE, { numeric: "auto" });

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

export function formatDateTime(value: string | Date): string {
  return dateTimeFormat.format(new Date(value));
}

export function formatRelative(value: string | Date, now = Date.now()): string {
  const seconds = (new Date(value).getTime() - now) / 1000;
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) {
      return relativeFormat.format(Math.round(seconds / size), unit);
    }
  }
  return "vừa xong";
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}
