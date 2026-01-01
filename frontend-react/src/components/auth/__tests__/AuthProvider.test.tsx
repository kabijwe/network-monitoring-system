import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { AuthProvider } from '../AuthProvider';
import { authSlice } from '../../../store/slices/authSlice';

// Mock the auth utilities
jest.mock('../../../utils/auth', () => ({
  tokenStorage: {
    get: jest.fn(),
    remove: jest.fn(),
  },
  isTokenExpired: jest.fn(),
}));

// Mock the API hooks
jest.mock('../../../store/api/authApi', () => ({
  useGetCurrentUserQuery: jest.fn(),
  useVerifyTokenMutation: jest.fn(),
}));

const mockTokenStorage = require('../../../utils/auth').tokenStorage;
const mockIsTokenExpired = require('../../../utils/auth').isTokenExpired;
const mockUseGetCurrentUserQuery = require('../../../store/api/authApi').useGetCurrentUserQuery;
const mockUseVerifyTokenMutation = require('../../../store/api/authApi').useVerifyTokenMutation;

const createMockStore = () => {
  return configureStore({
    reducer: {
      auth: authSlice.reducer,
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware({
        serializableCheck: {
          ignoredActions: ['persist/PERSIST'],
        },
      }),
  });
};

const TestComponent = () => <div data-testid="protected-content">Protected Content</div>;

describe('AuthProvider', () => {
  let mockStore: ReturnType<typeof createMockStore>;
  let mockVerifyToken: jest.Mock;

  beforeEach(() => {
    mockStore = createMockStore();
    mockVerifyToken = jest.fn();
    
    // Reset all mocks
    jest.clearAllMocks();
    
    // Default mock implementations
    mockTokenStorage.get.mockReturnValue(null);
    mockTokenStorage.remove.mockImplementation(() => {});
    mockIsTokenExpired.mockReturnValue(false);
    mockUseVerifyTokenMutation.mockReturnValue([mockVerifyToken, {}]);
    mockUseGetCurrentUserQuery.mockReturnValue({
      data: null,
      error: null,
      isLoading: false,
    });
  });

  const renderWithProvider = (component: React.ReactElement) => {
    return render(
      <Provider store={mockStore}>
        {component}
      </Provider>
    );
  };

  it('shows loading screen during initialization', () => {
    mockUseGetCurrentUserQuery.mockReturnValue({
      data: null,
      error: null,
      isLoading: true,
    });

    renderWithProvider(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    expect(screen.getByText('WorldLink NMS')).toBeInTheDocument();
    expect(screen.getByText('Initializing application...')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('clears credentials when no tokens are found', async () => {
    mockTokenStorage.get.mockReturnValue(null);

    renderWithProvider(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });

    expect(mockTokenStorage.remove).not.toHaveBeenCalled();
  });

  it('clears credentials when access token is expired and no refresh token', async () => {
    mockTokenStorage.get.mockReturnValue({
      access: 'expired-token',
      refresh: null,
    });
    mockIsTokenExpired.mockReturnValue(true);

    renderWithProvider(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });

    expect(mockTokenStorage.remove).toHaveBeenCalled();
  });

  it('clears credentials when both tokens are expired', async () => {
    mockTokenStorage.get.mockReturnValue({
      access: 'expired-token',
      refresh: 'expired-refresh-token',
    });
    mockIsTokenExpired.mockReturnValue(true);

    renderWithProvider(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });

    expect(mockTokenStorage.remove).toHaveBeenCalled();
  });

  it('verifies valid tokens with server', async () => {
    const mockTokens = {
      access: 'valid-token',
      refresh: 'valid-refresh-token',
    };
    
    mockTokenStorage.get.mockReturnValue(mockTokens);
    mockIsTokenExpired.mockReturnValue(false);
    mockVerifyToken.mockResolvedValue({ success: true });

    renderWithProvider(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });

    expect(mockVerifyToken).toHaveBeenCalledWith({ token: 'valid-token' });
  });

  it('allows refresh token flow when access token is expired', async () => {
    const mockTokens = {
      access: 'expired-token',
      refresh: 'valid-refresh-token',
    };

    mockTokenStorage.get.mockReturnValue(mockTokens);
    mockIsTokenExpired
      .mockReturnValueOnce(true) // access token expired
      .mockReturnValueOnce(false); // refresh token valid

    renderWithProvider(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });

    // Should not remove tokens, allowing refresh flow
    expect(mockTokenStorage.remove).not.toHaveBeenCalled();
  });
});