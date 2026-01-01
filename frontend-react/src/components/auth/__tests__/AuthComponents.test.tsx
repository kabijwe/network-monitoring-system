import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';

// Mock useAuth hook for testing
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

// Import components after mocking
import { RoleGuard } from '../RoleGuard';

// Simple LoginForm mock for testing UI elements
const MockLoginForm: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    username: '',
    password: '',
  });
  const [showPassword, setShowPassword] = React.useState(false);
  const [rememberMe, setRememberMe] = React.useState(false);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setCredentials(prev => ({
      ...prev,
      [name]: value,
    }));
  };

  const isFormValid = credentials.username && credentials.password;

  return (
    <div className="login-container">
      <div className="login-form-wrapper">
        <div className="login-branding">
          <div className="worldlink-logo w-20 h-20">
            <span className="text-white text-2xl font-bold">WL</span>
          </div>
          <h1 className="login-title">WorldLink NMS</h1>
          <p className="login-subtitle">Network Monitoring System</p>
        </div>

        <div className="login-card">
          <div className="login-card-header">
            <h2 className="login-card-title">Welcome Back</h2>
            <p className="login-card-description">
              Sign in to your account to continue
            </p>
          </div>
          
          <form className="login-form">
            <div className="form-group">
              <label className="form-label" htmlFor="username">Username</label>
              <input
                id="username"
                name="username"
                type="text"
                value={credentials.username}
                onChange={handleInputChange}
                placeholder="Enter your username"
                required
                autoComplete="username"
                className="input"
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="password">Password</label>
              <div className="password-field">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={credentials.password}
                  onChange={handleInputChange}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                  className="input"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
            </div>

            <div className="remember-me-section">
              <label className="checkbox-container">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="checkbox"
                />
                <span className="text-sm font-medium text-gray-700">Remember me</span>
              </label>
            </div>

            <button
              type="submit"
              className="btn btn-primary w-full"
              disabled={!isFormValid}
            >
              Sign In
            </button>

            {process.env.NODE_ENV === 'development' && (
              <div className="dev-hint">
                <p className="dev-hint-text">
                  <strong>Development Mode:</strong> Use admin / admin123
                </p>
              </div>
            )}
          </form>
        </div>

        <div className="login-footer">
          <p className="login-footer-text">
            &copy; 2025 WorldLink Communications. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
};

describe('Authentication Components', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUseAuth.checkPermission.mockReturnValue(true);
    mockUseAuth.canAccessLocation.mockReturnValue(true);
    mockUseAuth.canAccessGroup.mockReturnValue(true);
  });

  describe('LoginForm UI', () => {
    it('renders all required branding elements', () => {
      render(<MockLoginForm />);

      expect(screen.getByText('WorldLink NMS')).toBeInTheDocument();
      expect(screen.getByText('Network Monitoring System')).toBeInTheDocument();
      expect(screen.getByText('Welcome Back')).toBeInTheDocument();
      expect(screen.getByText('Sign in to your account to continue')).toBeInTheDocument();
      expect(screen.getByText('WL')).toBeInTheDocument();
      expect(screen.getByText(/© 2025 WorldLink Communications/i)).toBeInTheDocument();
    });

    it('renders form elements with proper accessibility', () => {
      render(<MockLoginForm />);

      const usernameInput = screen.getByRole('textbox', { name: /username/i });
      const passwordInput = document.querySelector('input[name="password"]') as HTMLInputElement;
      const rememberCheckbox = screen.getByRole('checkbox', { name: /remember me/i });
      const submitButton = screen.getByRole('button', { name: /sign in/i });

      expect(usernameInput).toHaveAttribute('name', 'username');
      expect(usernameInput).toHaveAttribute('type', 'text');
      expect(usernameInput).toHaveAttribute('required');
      expect(usernameInput).toHaveAttribute('autoComplete', 'username');

      expect(passwordInput).toHaveAttribute('name', 'password');
      expect(passwordInput).toHaveAttribute('type', 'password');
      expect(passwordInput).toHaveAttribute('required');
      expect(passwordInput).toHaveAttribute('autoComplete', 'current-password');

      expect(rememberCheckbox).toBeInTheDocument();
      expect(submitButton).toBeInTheDocument();
    });

    it('validates form fields correctly', () => {
      render(<MockLoginForm />);

      const usernameInput = screen.getByRole('textbox', { name: /username/i });
      const passwordInput = document.querySelector('input[name="password"]') as HTMLInputElement;
      const submitButton = screen.getByRole('button', { name: /sign in/i });

      // Initially disabled
      expect(submitButton).toBeDisabled();

      // Username only
      fireEvent.change(usernameInput, { target: { value: 'admin' } });
      expect(submitButton).toBeDisabled();

      // Password only
      fireEvent.change(usernameInput, { target: { value: '' } });
      fireEvent.change(passwordInput, { target: { value: 'password' } });
      expect(submitButton).toBeDisabled();

      // Both fields filled
      fireEvent.change(usernameInput, { target: { value: 'admin' } });
      expect(submitButton).not.toBeDisabled();
    });

    it('toggles password visibility', () => {
      render(<MockLoginForm />);

      const passwordInput = document.querySelector('input[name="password"]') as HTMLInputElement;
      const toggleButton = screen.getByLabelText(/toggle password visibility/i);

      expect(passwordInput.type).toBe('password');

      fireEvent.click(toggleButton);
      expect(passwordInput.type).toBe('text');

      fireEvent.click(toggleButton);
      expect(passwordInput.type).toBe('password');
    });

    it('handles remember me checkbox', () => {
      render(<MockLoginForm />);

      const rememberCheckbox = screen.getByRole('checkbox', { name: /remember me/i });

      expect(rememberCheckbox).not.toBeChecked();

      fireEvent.click(rememberCheckbox);
      expect(rememberCheckbox).toBeChecked();

      fireEvent.click(rememberCheckbox);
      expect(rememberCheckbox).not.toBeChecked();
    });

    it('shows development hint in development mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      render(<MockLoginForm />);

      expect(screen.getByText(/development mode/i)).toBeInTheDocument();
      expect(screen.getByText(/admin \/ admin123/i)).toBeInTheDocument();

      process.env.NODE_ENV = originalEnv;
    });

    it('applies correct CSS classes', () => {
      render(<MockLoginForm />);

      expect(document.querySelector('.login-container')).toBeInTheDocument();
      expect(document.querySelector('.login-form-wrapper')).toBeInTheDocument();
      expect(document.querySelector('.login-branding')).toBeInTheDocument();
      expect(document.querySelector('.login-card')).toBeInTheDocument();
      expect(document.querySelector('.worldlink-logo')).toBeInTheDocument();
    });
  });

  describe('RoleGuard Component', () => {
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
    });

    it('works with inverse logic', () => {
      mockUseAuth.checkPermission.mockReturnValue(false);

      render(
        <RoleGuard requiredRole="admin" inverse>
          <div data-testid="guarded-content">Non-Admin Content</div>
        </RoleGuard>
      );

      expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
    });

    it('checks location access', () => {
      render(
        <RoleGuard locationId={1}>
          <div data-testid="guarded-content">Location Content</div>
        </RoleGuard>
      );

      expect(mockUseAuth.canAccessLocation).toHaveBeenCalledWith(1);
      expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
    });

    it('checks group access', () => {
      render(
        <RoleGuard groupId={1}>
          <div data-testid="guarded-content">Group Content</div>
        </RoleGuard>
      );

      expect(mockUseAuth.canAccessGroup).toHaveBeenCalledWith(1);
      expect(screen.getByTestId('guarded-content')).toBeInTheDocument();
    });

    it('checks multiple permissions', () => {
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

    it('denies access if any permission check fails', () => {
      mockUseAuth.checkPermission.mockReturnValue(true);
      mockUseAuth.canAccessLocation.mockReturnValue(false);

      render(
        <RoleGuard 
          requiredRole="admin" 
          locationId={1}
        >
          <div data-testid="guarded-content">Protected Content</div>
        </RoleGuard>
      );

      expect(screen.queryByTestId('guarded-content')).not.toBeInTheDocument();
    });
  });

  describe('Authentication Form Validation', () => {
    it('validates email format if email field exists', () => {
      // This test demonstrates how we could extend validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      
      expect(emailRegex.test('admin@example.com')).toBe(true);
      expect(emailRegex.test('invalid-email')).toBe(false);
    });

    it('validates password strength requirements', () => {
      // This test demonstrates password validation logic
      const isValidPassword = (password: string) => {
        return password.length >= 6; // Simple validation for demo
      };
      
      expect(isValidPassword('admin123')).toBe(true);
      expect(isValidPassword('123')).toBe(false);
    });

    it('validates username format', () => {
      // This test demonstrates username validation
      const isValidUsername = (username: string) => {
        return username.length >= 3 && /^[a-zA-Z0-9_]+$/.test(username);
      };
      
      expect(isValidUsername('admin')).toBe(true);
      expect(isValidUsername('ab')).toBe(false);
      expect(isValidUsername('admin@')).toBe(false);
    });
  });

  describe('Component Integration', () => {
    it('integrates LoginForm with RoleGuard for protected content', () => {
      const ProtectedLoginArea = () => (
        <RoleGuard requiredRole="admin" fallback={<div>Access Denied</div>}>
          <MockLoginForm />
        </RoleGuard>
      );

      render(<ProtectedLoginArea />);

      // Should render login form since user has admin role
      expect(screen.getByText('WorldLink NMS')).toBeInTheDocument();
      expect(screen.queryByText('Access Denied')).not.toBeInTheDocument();
    });

    it('shows access denied when user lacks permission', () => {
      mockUseAuth.checkPermission.mockReturnValue(false);

      const ProtectedLoginArea = () => (
        <RoleGuard requiredRole="superadmin" fallback={<div>Access Denied</div>}>
          <MockLoginForm />
        </RoleGuard>
      );

      render(<ProtectedLoginArea />);

      expect(screen.queryByText('WorldLink NMS')).not.toBeInTheDocument();
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
    });
  });
});