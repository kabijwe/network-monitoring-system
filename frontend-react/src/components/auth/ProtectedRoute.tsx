import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { Alert, AlertDescription } from '../ui/Alert';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
  requiredPermission?: string;
  locationId?: number;
  groupId?: number;
  fallbackPath?: string;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRole,
  requiredPermission,
  locationId,
  groupId,
  fallbackPath = '/login',
}) => {
  const location = useLocation();
  const {
    isAuthenticated,
    isLoading,
    checkPermission,
    canAccessLocation,
    canAccessGroup,
  } = useAuth();

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to={fallbackPath} state={{ from: location }} replace />;
  }

  // Check role-based permissions
  if (requiredRole && !checkPermission(requiredRole)) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="max-w-md w-full">
          <Alert variant="destructive">
            <AlertDescription>
              You don't have permission to access this page. Required role: {requiredRole}
            </AlertDescription>
          </Alert>
        </div>
      </div>
    );
  }

  // Check specific permission
  if (requiredPermission && !checkPermission(requiredPermission)) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="max-w-md w-full">
          <Alert variant="destructive">
            <AlertDescription>
              You don't have the required permission to access this page.
            </AlertDescription>
          </Alert>
        </div>
      </div>
    );
  }

  // Check location access
  if (locationId && !canAccessLocation(locationId)) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="max-w-md w-full">
          <Alert variant="destructive">
            <AlertDescription>
              You don't have access to this location.
            </AlertDescription>
          </Alert>
        </div>
      </div>
    );
  }

  // Check group access
  if (groupId && !canAccessGroup(groupId)) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="max-w-md w-full">
          <Alert variant="destructive">
            <AlertDescription>
              You don't have access to this group.
            </AlertDescription>
          </Alert>
        </div>
      </div>
    );
  }

  // All checks passed, render the protected content
  return <>{children}</>;
};