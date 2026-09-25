import {
  MutationCache,
  QueryClient,
  type DefaultOptions,
  type UseMutationOptions,
} from "@tanstack/react-query";
import { toast } from "sonner";
import { isApiError } from "@/lib/api-client";

declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: {
      /** Set when the component renders the error itself, e.g. inside a form. */
      handlesError?: boolean;
    };
  }
}

export const queryConfig = {
  queries: {
    staleTime: 30_000,
    // Retrying cannot fix a 4xx such as 404 or 422; only retry transient failures.
    retry: (failureCount, error) =>
      failureCount < 2 &&
      !(isApiError(error) && error.status >= 400 && error.status < 500),
  },
} satisfies DefaultOptions;

/** Queries render errors in place; mutations toast unless the caller shows the error. */
export function createQueryClient(
  defaultOptions: DefaultOptions = queryConfig,
) {
  return new QueryClient({
    defaultOptions,
    mutationCache: new MutationCache({
      onError: (error, _variables, _context, mutation) => {
        if (!mutation.meta?.handlesError) toast.error(error.message);
      },
    }),
  });
}

/** Options a caller may pass to a feature's query hook. */
export type QueryConfig<T extends (...args: never[]) => unknown> = Omit<
  ReturnType<T>,
  "queryKey" | "queryFn"
>;

export type ApiFnReturnType<
  FnType extends (...args: never[]) => Promise<unknown>,
> = Awaited<ReturnType<FnType>>;

/** Options a caller may pass to a feature's mutation hook. */
export type MutationConfig<
  MutationFnType extends (...args: never[]) => Promise<unknown>,
> = UseMutationOptions<
  ApiFnReturnType<MutationFnType>,
  Error,
  Parameters<MutationFnType>[0]
>;
