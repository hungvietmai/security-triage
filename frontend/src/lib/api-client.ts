import { env } from "@/config/env";
import type { Schemas } from "@/types/api";

const TIMEOUT_MS = 15_000;

/** Error raised for any failed API call; `status` is 0 when the request never reached the API. */
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function isApiError(error: unknown, status?: number): error is ApiError {
  return (
    error instanceof ApiError &&
    (status === undefined || error.status === status)
  );
}

type ValidationIssue = Partial<Schemas["ValidationError"]>;

/** Turn a FastAPI error body ({detail: string | ValidationIssue[]}) into a readable message. */
async function errorMessage(response: Response): Promise<string> {
  const fallback =
    response.status >= 500
      ? `Máy chủ lỗi (${response.status}). Kiểm tra API và các dịch vụ phụ thuộc.`
      : `Yêu cầu thất bại (${response.status}).`;
  try {
    const { detail } = (await response.json()) as {
      detail?: string | ValidationIssue[];
    };
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length) {
      return detail
        .map(({ loc, msg }) => {
          const field = loc?.filter((part) => part !== "body").join(".");
          return field ? `${field}: ${msg ?? ""}` : (msg ?? "");
        })
        .join("; ");
    }
  } catch {
    // Non-JSON body, e.g. an Nginx 502 page.
  }
  return fallback;
}

type QueryParams = Record<string, string | number | boolean | undefined>;

export interface RequestOptions extends Omit<RequestInit, "body"> {
  params?: QueryParams;
  json?: unknown;
  /** Status codes whose JSON body is returned instead of raising, e.g. 503 from readiness. */
  acceptStatus?: number[];
}

function buildUrl(path: string, params?: QueryParams): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined) search.set(key, String(value));
  }
  const query = search.toString();
  return `${env.API_URL}${path}${query ? `?${query}` : ""}`;
}

/** Single entry point for API calls: timeout, JSON handling and error normalization. */
export async function apiRequest<T>(
  path: string,
  {
    params,
    json,
    acceptStatus = [],
    headers,
    signal,
    ...init
  }: RequestOptions = {},
): Promise<T> {
  const timeout = AbortSignal.timeout(TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(buildUrl(path, params), {
      ...init,
      headers:
        json === undefined
          ? headers
          : { "Content-Type": "application/json", ...headers },
      body: json === undefined ? undefined : JSON.stringify(json),
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    });
  } catch (cause) {
    // Let TanStack Query see its own cancellations unchanged.
    if (signal?.aborted) throw cause;
    throw new ApiError("Không kết nối được API.", 0);
  }
  if (!response.ok && !acceptStatus.includes(response.status)) {
    throw new ApiError(await errorMessage(response), response.status);
  }
  return response.json() as Promise<T>;
}

type MethodOptions = Omit<RequestOptions, "method" | "json">;

export const api = {
  get: <T>(path: string, options?: MethodOptions) =>
    apiRequest<T>(path, { ...options, method: "GET" }),
  post: <T>(path: string, body?: unknown, options?: MethodOptions) =>
    apiRequest<T>(path, { ...options, method: "POST", json: body }),
};
