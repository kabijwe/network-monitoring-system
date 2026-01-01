import { AuthTokens } from '../types';

const TOKEN_KEY = 'nms_tokens';

export const tokenStorage = {
  get: (): AuthTokens | null => {
    try {
      const tokens = localStorage.getItem(TOKEN_KEY);
      return tokens ? JSON.parse(tokens) : null;
    } catch {
      return null;
    }
  },
  
  set: (tokens: AuthTokens): void => {
    localStorage.setItem(TOKEN_KEY, JSON.stringify(tokens));
  },
  
  remove: (): void => {
    localStorage.removeItem(TOKEN_KEY);
  },
};

export const isTokenExpired = (token: string): boolean => {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const currentTime = Date.now() / 1000;
    return payload.exp < currentTime;
  } catch {
    return true;
  }
};

export const hasPermission = (
  userRoles: Array<{ role: string }>,
  requiredRole: string
): boolean => {
  const roleHierarchy = {
    'viewer': 1,
    'editor': 2,
    'admin': 3,
    'superadmin': 4,
  };
  
  const userMaxRole = Math.max(
    ...userRoles.map(r => roleHierarchy[r.role.toLowerCase() as keyof typeof roleHierarchy] || 0)
  );
  
  const requiredRoleLevel = roleHierarchy[requiredRole.toLowerCase() as keyof typeof roleHierarchy] || 0;
  
  return userMaxRole >= requiredRoleLevel;
};