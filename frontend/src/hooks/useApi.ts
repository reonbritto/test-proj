import { useQuery, UseQueryResult } from '@tanstack/react-query';
import { fetchAPI } from '../utils/api';

/**
 * Generic hook for authenticated API calls with React Query.
 */
export function useApi<T>(
  key: string | string[],
  url: string,
  options?: { enabled?: boolean }
): UseQueryResult<T> {
  return useQuery<T>({
    queryKey: Array.isArray(key) ? key : [key],
    queryFn: () => fetchAPI<T>(url),
    enabled: options?.enabled,
    staleTime: 60_000, // 1 min
    retry: 1,
  });
}
