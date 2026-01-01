import React from 'react';
import { render, screen } from '@testing-library/react';
import { RoleGuard } from '../RoleGuard';

// Mock the useAuth hook
const mockUseAuth = {
  checkPermission: jest.fn(),
  canAccessLocation: jest.fn(),
  canAccessGroup: jest.fn(),
};

jest.mock('../../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth,
}));

describe('RoleGuard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset mock defaults
    mockUseAuth.checkPermission.mockReturnValue(true);
    mockUseAuth.canAccessLocation.mockReturnValue(true);
    mockUseAuth.canAccessGroup.mockReturnValue(true);
  });

  it('renders children when no permissions are required', () => {
    render(
      <RoleGuard>
        <div data-testid="guarded-content">Guarded Content</div>
      </RoleGuard>
    );

    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('renders children when user has required role', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);

    render(
      <RoleGuard requiredRole="admin">
        <div data-testid="guarded-content">Admin Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('does not render children when user lacks required role', () => {
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <RoleGuard requiredRole="admin">
        <div data-testid="guarded-content">Admin Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.queryByTestId('guarded-content')).not.toBeInTheDocument();
  });

  it('renders fallback when user lacks required role', () => {
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <RoleGuard 
        requiredRole="admin"
        fallback={<div data-testid="fallback-content">Access Denied</div>}
      >
        <div data-testid="guarded-content">Admin Content</div>
      </RoleGuard>
    );

    expect(screen.queryByTestId('guarded-content')).not.toBeInTheDocument();
    expect(screen.getByTestId('fallback-content')).toBeInTheDocument();
    expect(screen.getByText('Access Denied')).toBeInTheDocument();
  });

  it('renders children when user has required permission', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);

    render(
      <RoleGuard requiredPermission="view_hosts">
        <div data-testid="guarded-content">Host Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('view_hosts');
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('renders children when user has access to required location', () => {
    mockUseAuth.canAccessLocation.mockReturnValue(true);

    render(
      <RoleGuard locationId={1}>
        <div data-testid="guarded-content">Location Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('renders children when user has access to required group', () => {
    mockUseAuth.canAccessGroup.mockReturnValue(true);

    render(
      <RoleGuard groupId={1}>
        <div data-testid="guarded-content">Group Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('checks multiple permissions when all are specified', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);
    mockUseAuth.canAccessLocation.mockReturnValue(true);
    mockUseAuth.canAccessGroup.mockReturnValue(true);

    render(
      <RoleGuard 
        requiredRole="admin" 
        requiredPermission="view_hosts"
        locationId={1}
        groupId={1}
      >
        <div data-testid="guarded-content">Multi-Protected Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('view_hosts');
    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('does not render children if any permission check fails', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);
    mockUseAuth.canAccessLocation.mockReturnValue(false); // This one fails
    mockUseAuth.canAccessGroup.mockReturnValue(true);

    render(
      <RoleGuard 
        requiredRole="admin" 
        locationId={1}
        groupId={1}
      >
        <div data-testid="guarded-content">Multi-Protected Content</div>
      </RoleGuard>
    );

    expect(screen.queryByTestId('guarded-content')).not.toBeInTheDocument();
  });

  it('works with inverse logic - shows content when user DOES NOT have permission', () => {
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <RoleGuard requiredRole="admin" inverse>
        <div data-testid="guarded-content">Non-Admin Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('works with inverse logic - hides content when user HAS permission', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);

    render(
      <RoleGuard requiredRole="admin" inverse>
        <div data-testid="guarded-content">Non-Admin Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.queryByTestId('guarded-content')).not.toBeInTheDocument();
  });

  it('renders fallback with inverse logic when user has permission', () => {
    mockUseAuth.checkPermission.mockReturnValue(true);

    render(
      <RoleGuard 
        requiredRole="admin" 
        inverse
        fallback={<div data-testid="fallback-content">Admin Detected</div>}
      >
        <div data-testid="guarded-content">Non-Admin Content</div>
      </RoleGuard>
    );

    expect(screen.queryByTestId('guarded-content')).not.toBeInTheDocument();
    expect(screen.getByTestId('fallback-content')).toBeInTheDocument();
    expect(screen.getByText('Admin Detected')).toBeInTheDocument();
  });
});