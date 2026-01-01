import React from 'react';
import { render, screen } from '@testing-library/react';
import { RoleGuard } from '../RoleGuard';

// Mock the useAuth hook with simple return values
const mockUseAuth = {
  checkPermission: jest.fn(() => true),
  canAccessLocation: jest.fn(() => true),
  canAccessGroup: jest.fn(() => true),
};

jest.mock('../../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth,
}));

describe('RoleGuard Basic Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
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

  it('works with inverse logic', () => {
    mockUseAuth.checkPermission.mockReturnValue(false);

    render(
      <RoleGuard requiredRole="admin" inverse>
        <div data-testid="guarded-content">Non-Admin Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.checkPermission).toHaveBeenCalledWith('admin');
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('checks location access when locationId is provided', () => {
    render(
      <RoleGuard locationId={1}>
        <div data-testid="guarded-content">Location Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });

  it('checks group access when groupId is provided', () => {
    render(
      <RoleGuard groupId={1}>
        <div data-testid="guarded-content">Group Content</div>
      </RoleGuard>
    );

    expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
    expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
  });
});