import React from 'react';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { useLogoutMutation } from '../../store/api/authApi';
import { clearCredentials } from '../../store/slices/authSlice';
import { tokenStorage } from '../../utils/auth';
import { Button } from '../ui/Button';

interface LogoutButtonProps {
  variant?: 'default' | 'ghost' | 'outline';
  size?: 'default' | 'sm' | 'lg';
  className?: string;
  children?: React.ReactNode;
}

export const LogoutButton: React.FC<LogoutButtonProps> = ({
  variant = 'ghost',
  size = 'default',
  className,
  children = 'Sign Out',
}) => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [logout, { isLoading }] = useLogoutMutation();

  const handleLogout = async () => {
    try {
      // Call logout endpoint to invalidate token on server
      await logout().unwrap();
    } catch (error) {
      // Even if server logout fails, we still clear local state
      console.warn('Server logout failed:', error);
    } finally {
      // Clear local storage and Redux state
      tokenStorage.remove();
      dispatch(clearCredentials());
      
      // Navigate to login page
      navigate('/login', { replace: true });
    }
  };

  return (
    <Button
      variant={variant}
      size={size}
      className={className}
      onClick={handleLogout}
      disabled={isLoading}
    >
      {isLoading ? (
        <div className="flex items-center space-x-2">
          <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
          <span>Signing out...</span>
        </div>
      ) : (
        children
      )}
    </Button>
  );
};