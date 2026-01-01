import React from 'react';
import { useAuth } from '../../hooks/useAuth';

interface RoleGuardProps {
  children: React.ReactNode;
  requiredRole?: string;
  requiredPermission?: string;
  locationId?: number;
  groupId?: number;
  fallback?: React.ReactNode;
  inverse?: boolean; // Show content when user DOESN'T have permission
}

export const RoleGuard: React.FC<RoleGuardProps> = ({
  children,
  requiredRole,
  requiredPermission,
  locationId,
  groupId,
  fallback = null,
  inverse = false,
}) => {
  const {
    checkPermission,
    canAccessLocation,
    canAccessGroup,
  } = useAuth();

  let hasAccess = true;

  // Check role-based permissions
  if (requiredRole) {
    hasAccess = hasAccess && checkPermission(requiredRole);
  }

  // Check specific permission
  if (requiredPermission) {
    hasAccess = hasAccess && checkPermission(requiredPermission);
  }

  // Check location access
  if (locationId) {
    hasAccess = hasAccess && canAccessLocation(locationId);
  }

  // Check group access
  if (groupId) {
    hasAccess = hasAccess && canAccessGroup(groupId);
  }

  // Apply inverse logic if specified
  if (inverse) {
    hasAccess = !hasAccess;
  }

  return hasAccess ? <>{children}</> : <>{fallback}</>;
};