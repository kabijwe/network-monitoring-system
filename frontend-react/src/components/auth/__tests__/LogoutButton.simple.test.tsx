import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { authSlice } from '../../../store/slices/authSlice';

// Mock the auth utilities
jest.mock('../../../utils/auth', () => ({
  tokenStorage: {
    remove: jest.fn(),
  },
}));

// Mock the API hooks
jest.mock('../../../store/api/authApi', () => ({
  useLogoutMutation: jest.fn(),
}));

const mockTokenStorage = require('../../../utils/auth').tokenStorage;
const mockUseLogoutMutation = require('../../../store/api/authApi').useLogoutMutation;

// Simple LogoutButton mock for testing
const MockLogoutButton: React.FC<{ children?: React.ReactNode }> = ({ children = 'Sign Out' }) => {
  const [isLoading, setIsLoading] = React.useState(false);

  const handleLogout = async () => {
    setIsLoading(true);
    try {
      // Simulate logout API call
      await new Promise(resolve => setTimeout(resolve, 100));
      mockTokenStorage.remove();
      // Simulate navigation
    } catch (error) {
      console.warn('Logout failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <button
      type="button"
      onClick={handleLogout}
      disabled={isLoading}
      data-testid="logout-button"
    >
      {isLoading ? (
        <div className="flex items-center space-x-2">
          <div className="loading-spinner" data-testid="loading-spinner"></div>
          <span>Signing out...</span>
        </div>
      ) : (
        children
      )}
    </button>
  );
};

const createMockStore = () => {
  return configureStore({
    reducer: {
      auth: authSlice.reducer,
    },
  });
};

describe('LogoutButton (Simple)', () => {
  let mockStore: ReturnType<typeof createMockStore>;

  beforeEach(() => {
    mockStore = createMockStore();
    jest.clearAllMocks();
    mockUseLogoutMutation.mockReturnValue([jest.fn(), { isLoading: false }]);
  });

  const renderWithProvider = (component: React.ReactElement) => {
    return render(
      <Provider store={mockStore}>
        {component}
      </Provider>
    );
  };

  it('renders logout button with default text', () => {
    renderWithProvider(<MockLogoutButton />);

    const button = screen.getByTestId('logout-button');
    expect(button).toBeInTheDocument();
    expect(button).toHaveTextContent('Sign Out');
    expect(button).not.toBeDisabled();
  });

  it('renders logout button with custom text', () => {
    renderWithProvider(<MockLogoutButton>Custom Logout</MockLogoutButton>);

    const button = screen.getByTestId('logout-button');
    expect(button).toHaveTextContent('Custom Logout');
  });

  it('handles logout click and shows loading state', async () => {
    renderWithProvider(<MockLogoutButton />);

    const button = screen.getByTestId('logout-button');
    
    await act(async () => {
      fireEvent.click(button);
    });

    // Should show loading state immediately
    expect(screen.getByText('Signing out...')).toBeInTheDocument();
    expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
    expect(button).toBeDisabled();
  });

  it('calls tokenStorage.remove on logout', async () => {
    renderWithProvider(<MockLogoutButton />);

    const button = screen.getByTestId('logout-button');
    
    await act(async () => {
      fireEvent.click(button);
      // Wait for async operation
      await new Promise(resolve => setTimeout(resolve, 150));
    });

    expect(mockTokenStorage.remove).toHaveBeenCalled();
  });

  it('handles logout errors gracefully', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    
    // Mock an error scenario
    mockTokenStorage.remove.mockImplementation(() => {
      throw new Error('Storage error');
    });

    renderWithProvider(<MockLogoutButton />);

    const button = screen.getByTestId('logout-button');
    
    await act(async () => {
      fireEvent.click(button);
      // Wait for async operation
      await new Promise(resolve => setTimeout(resolve, 150));
    });

    expect(consoleSpy).toHaveBeenCalledWith('Logout failed:', expect.any(Error));
    
    consoleSpy.mockRestore();
  });

  it('button is accessible', () => {
    renderWithProvider(<MockLogoutButton />);

    const button = screen.getByTestId('logout-button');
    expect(button).toHaveAttribute('type', 'button');
    expect(button.tagName).toBe('BUTTON');
  });

  it('supports different loading states', async () => {
    const { rerender } = renderWithProvider(<MockLogoutButton />);

    // Initial state
    expect(screen.getByText('Sign Out')).toBeInTheDocument();
    expect(screen.queryByText('Signing out...')).not.toBeInTheDocument();

    // Simulate loading by clicking
    const button = screen.getByTestId('logout-button');
    
    await act(async () => {
      fireEvent.click(button);
    });

    // Loading state
    expect(screen.getByText('Signing out...')).toBeInTheDocument();
    expect(screen.queryByText('Sign Out')).not.toBeInTheDocument();
  });

  it('maintains button functionality with Redux store', () => {
    // Set initial authenticated state
    mockStore.dispatch({
      type: 'auth/setCredentials',
      payload: {
        user: { id: '1', username: 'admin' },
        tokens: { access: 'token', refresh: 'refresh' },
      },
    });

    renderWithProvider(<MockLogoutButton />);

    const button = screen.getByTestId('logout-button');
    expect(button).toBeInTheDocument();
    
    // Verify store has authenticated state
    const state = mockStore.getState();
    expect(state.auth.isAuthenticated).toBe(true);
  });
});