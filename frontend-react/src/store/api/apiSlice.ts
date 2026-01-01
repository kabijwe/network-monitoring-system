import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { BaseQueryFn, FetchArgs, FetchBaseQueryError } from '@reduxjs/toolkit/query';
import { RootState } from '../index';
import { setTokens, clearCredentials } from '../slices/authSlice';

const baseQuery = fetchBaseQuery({
  baseUrl: process.env.REACT_APP_API_URL || 'http://localhost:8000/api/',
  prepareHeaders: (headers, { getState }) => {
    const token = (getState() as RootState).auth.tokens?.access;
    if (token) {
      headers.set('authorization', `Bearer ${token}`);
    }
    headers.set('Content-Type', 'application/json');
    return headers;
  },
});

const baseQueryWithReauth: BaseQueryFn<
  string | FetchArgs,
  unknown,
  FetchBaseQueryError
> = async (args, api, extraOptions) => {
  let result = await baseQuery(args, api, extraOptions);

  if (result.error && result.error.status === 401) {
    // Try to get a new token
    const refreshToken = (api.getState() as RootState).auth.tokens?.refresh;
    
    if (refreshToken) {
      const refreshResult = await baseQuery(
        {
          url: 'auth/token/refresh/',
          method: 'POST',
          body: { refresh: refreshToken },
        },
        api,
        extraOptions
      );

      if (refreshResult.data) {
        const tokens = refreshResult.data as { access: string; refresh: string };
        api.dispatch(setTokens(tokens));
        
        // Retry the original query
        result = await baseQuery(args, api, extraOptions);
      } else {
        api.dispatch(clearCredentials());
      }
    } else {
      api.dispatch(clearCredentials());
    }
  }

  return result;
};

export const apiSlice = createApi({
  reducerPath: 'api',
  baseQuery: baseQueryWithReauth,
  tagTypes: [
    'User',
    'Host',
    'Location',
    'DeviceGroup',
    'Alert',
    'Threshold',
    'MonitoringResult',
    'ActivityLog',
    'MaintenanceWindow',
    'NotificationChannel',
    'NotificationRule',
  ],
  endpoints: () => ({}),
});