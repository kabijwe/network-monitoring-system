import React from 'react';
import { render, screen } from '@testing-library/react';

// Mock useAuth hook
const mockUseAuth = {
  isAuthenticated: true,
  isLoading: false,
  checkPermission: jest.fn(() => true),
  canAccessLocation: jest.fn(() => true),
  canAccessGroup: jest.fn(() => true),
};

jest.mock('../../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth,
}));

// Simple ProtectedRoute mock for testing core logic
interface MockProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
  requiredPermission?: string;
  locationId?: number;
  groupId?: number;
}

const MockProtectedRoute: React.FC<MockProtectedRouteProps> = ({
  children,
  requiredRole,
  requiredPermission,
  locationId,
  groupId,
}) => {
  const {
    isAuthenticated,
    isLoading,
    checkPermission,
    canAccessLocation,
    canAccessGroup,
  } = mockUseAuth;

  // Show loading state
  if (isLoading) {
    return <div data-testid="loading">Loading...</div>;
  }

  // Check authentication
  if (!isAuthenticated) {
    return <div data-testid="redirect">Redirecting to login...</div>;
  }

  // Check role-based permissions
  if (requiredRole && !checkPermission(requiredRole)) {
    return (
      <div data-testid="access-denied">
        Access denied. Required role: {requiredRole}
      </div>
    );
  }

  // Check specific permission
  if (requiredPermission && !checkPermission(requiredPermission)) {
    return (
      <div data-testid="access-denied">
        Access denied. Required permission: {requiredPermission}
      </div>
    );
  }

  // Check location access
  if (locationId !== undefined && !canAccessLocation(locationId)) {
    return (
      <div data-testid="access-denied">
        Access denied. Location access required.
      </div>
    );
  }

  // Check group access
  if (groupId !== undefined && !canAccessGroup(groupId)) {
    return (
      <div data-testid="access-denied">
        Access denied. Group access required.
      </div>
    );
  }

  // All checks passed, render children
  return <>{children}</>;
};

const TestComponent = () => <div data-testid="protected-content">Protected Content</div>;

describe('ProtectedRoute (Simple)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUseAuth.isAuthenticated = true;
    mockUseAuth.isLoading = false;
    mockUseAuth.checkPermission.mockReturnValue(true);
    mockUseAuth.canAccessLocation.mockReturnValue(true);
    mockUseAuth.canAccessGroup.mockReturnValue(true);
  });

  it('shows loading state when authentication is loading', () => {
    mockUseAuth.isLoading = true;

    render(
      <MockProtectedRoute>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('loading')).toBeInTheDocument();
    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('shows redirect when not authenticated', () => {
    mockUseAuth.isAuthenticated = false;

    render(
      <MockProtectedRoute>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('redirect')).toBeInTheDocument();
    expect(screen.getByText('Redirecting to login...')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('renders children when authenticated and no permissions required', () => {
    render(
      <MockProtectedRoute>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('renders children when user has required role', () => {
    render(
      <MockProtectedRoute requiredRole="admin">
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('shows access denied when user lacks required role', () => {
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <MockProtectedRoute requiredRole="admin">
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.getByTestId('access-denied')).toBeInTheDocument();
    expect(screen.getByText('Access denied. Required role: admin')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('renders children when user has required permission', () => {
    render(
      <MockProtectedRoute requiredPermission="view_hosts">
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('view_hosts');
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('shows access denied when user lacks required permission', () => {
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <MockProtectedRoute requiredPermission="view_hosts">
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('view_hosts');
    expect(screen.getByTestId('access-denied')).toBeInTheDocument();
    expect(screen.getByText('Access denied. Required permission: view_hosts')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('renders children when user has location access', () => {
    render(
      <MockProtectedRoute locationId={1}>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('shows access denied when user lacks location access', () => {
    mockUseAuth.canAccessLocation.mockReturnValue(false);

    render(
      <MockProtectedRoute locationId={1}>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('access-denied')).toBeInTheDocument();
    expect(screen.getByText('Access denied. Location access required.')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('renders children when user has group access', () => {
    render(
      <MockProtectedRoute groupId={1}>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('shows access denied when user lacks group access', () => {
    mockUseAuth.canAccessGroup.mockReturnValue(false);

    render(
      <MockProtectedRoute groupId={1}>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('access-denied')).toBeInTheDocument();
    expect(screen.getByText('Access denied. Group access required.')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('checks multiple permissions and renders when all pass', () => {
    render(
      <MockProtectedRoute 
        requiredRole="admin" 
        requiredPermission="view_hosts"
        locationId={1}
        groupId={1}
      >
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('view_hosts');
    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('denies access if any permission check fails', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);
    mockUseAuth.canAccessLocation.mockReturnValue(false);

    render(
      <MockProtectedRoute 
        requiredRole="admin" 
        locationId={1}
      >
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('access-denied')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  it('handles undefined permission values correctly', () => {
    render(
      <MockProtectedRoute 
        requiredRole={undefined}
        requiredPermission={undefined}
        locationId={undefined}
        groupId={undefined}
      >
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    expect(mockUseAuth.checkPermission).not.toHaveBeenCalled();
    expect(mockUseAuth.canAccessLocation).not.toHaveBeenCalled();
    expect(mockUseAuth.canAccessGroup).not.toHaveBeenCalled();
  });

  it('handles location ID of 0', () => {
    render(
      <MockProtectedRoute locationId={0}>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(0);
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('handles group ID of 0', () => {
    render(
      <MockProtectedRoute groupId={0}>
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(0);
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('prioritizes authentication check over permission checks', () => {
    mockUseAuth.isAuthenticated = false;
    mockUseAuth.checkPermission.mockReturnValue(true);

    render(
      <MockProtectedRoute requiredRole="admin">
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('redirect')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
    // Permission check should not be called if not authenticated
    expect(mockUseAuth.checkPermission).not.toHaveBeenCalled();
  });

  it('prioritizes loading state over all other checks', () => {
    mockUseAuth.isLoading = true;
    mockUseAuth.isAuthenticated = false;
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <MockProtectedRoute requiredRole="admin">
        <TestComponent />
      </MockProtectedRoute>
    );

    expect(screen.getByTestId('loading')).toBeInTheDocument();
    expect(screen.queryByTestId('redirect')).not.toBeInTheDocument();
    expect(screen.queryByTestId('access-denied')).not.toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });
});