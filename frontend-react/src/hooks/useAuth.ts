import { useSelector } from 'react-redux';
import { RootState } from '../store';
import { hasPermission } from '../utils/auth';

export const useAuth = () => {
  const { user, tokens, isAuthenticated, isLoading, error } = useSelector(
    (state: RootState) => state.auth
  );

  const checkPermission = (requiredRole: string) => {
    if (!user?.roles) return false;
    return hasPermission(user.roles, requiredRole);
  };

  const hasRole = (role: string) => {
    if (!user?.roles) return false;
    return user.roles.some(userRole => userRole.role.toLowerCase() === role.toLowerCase());
  };

  const canAccessLocation = (locationId: number) => {
    if (!user?.roles) return false;
    
    // SuperAdmin and Admin can access all locations
    if (hasRole('superadmin') || hasRole('admin')) return true;
    
    // Check if user has specific location access
    return user.roles.some(role => 
      !role.location || role.location.id === locationId
    );
  };

  const canAccessGroup = (groupId: number) => {
    if (!user?.roles) return false;
    
    // SuperAdmin and Admin can access all groups
    if (hasRole('superadmin') || hasRole('admin')) return true;
    
    // Check if user has specific group access
    return user.roles.some(role => 
      !role.group || role.group.id === groupId
    );
  };

  const getAccessibleLocations = () => {
    if (!user?.roles) return [];
    
    // SuperAdmin and Admin can access all locations
    if (hasRole('superadmin') || hasRole('admin')) {
      return user.locations || [];
    }
    
    // Return only locations the user has explicit access to
    const accessibleLocationIds = user.roles
      .filter(role => role.location)
      .map(role => role.location!.id);
    
    return (user.locations || []).filter(location => 
      accessibleLocationIds.includes(location.id)
    );
  };

  const getAccessibleGroups = () => {
    if (!user?.roles) return [];
    
    // SuperAdmin and Admin can access all groups
    if (hasRole('superadmin') || hasRole('admin')) {
      return user.groups || [];
    }
    
    // Return only groups the user has explicit access to
    const accessibleGroupIds = user.roles
      .filter(role => role.group)
      .map(role => role.group!.id);
    
    return (user.groups || []).filter(group => 
      accessibleGroupIds.includes(group.id)
    );
  };

  const getHighestRole = () => {
    if (!user?.roles) return null;
    
    const roleHierarchy = {
      'viewer': 1,
      'editor': 2,
      'admin': 3,
      'superadmin': 4,
    };
    
    const highestRoleLevel = Math.max(
      ...user.roles.map(r => roleHierarchy[r.role.toLowerCase() as keyof typeof roleHierarchy] || 0)
    );
    
    const roleEntry = Object.entries(roleHierarchy).find(
      ([, level]) => level === highestRoleLevel
    );
    
    return roleEntry ? roleEntry[0] : null;
  };

  return {
    user,
    tokens,
    isAuthenticated,
    isLoading,
    error,
    checkPermission,
    hasRole,
    canAccessLocation,
    canAccessGroup,
    getAccessibleLocations,
    getAccessibleGroups,
    getHighestRole,
  };
};