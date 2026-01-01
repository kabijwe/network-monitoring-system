import { apiSlice } from './apiSlice';
import { LoginCredentials, User, AuthTokens } from '../../types';

export const authApi = apiSlice.injectEndpoints({
  endpoints: (builder) => ({
    login: builder.mutation<
      { user: User; access: string; refresh: string },
      LoginCredentials
    >({
      query: (credentials) => ({
        url: 'auth/token/',
        method: 'POST',
        body: credentials,
      }),
    }),
    
    logout: builder.mutation<void, void>({
      query: () => ({
        url: 'auth/logout/',
        method: 'POST',
      }),
    }),
    
    refreshToken: builder.mutation<AuthTokens, { refresh: string }>({
      query: ({ refresh }) => ({
        url: 'auth/token/refresh/',
        method: 'POST',
        body: { refresh },
      }),
    }),
    
    getCurrentUser: builder.query<User, void>({
      query: () => 'auth/user-info/',
      providesTags: ['User'],
    }),
    
    verifyToken: builder.mutation<{ valid: boolean }, { token: string }>({
      query: ({ token }) => ({
        url: 'auth/token/verify/',
        method: 'POST',
        body: { token },
      }),
    }),
  }),
});

export const {
  useLoginMutation,
  useLogoutMutation,
  useRefreshTokenMutation,
  useGetCurrentUserQuery,
  useVerifyTokenMutation,
} = authApi;