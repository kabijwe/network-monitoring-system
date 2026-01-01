import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { useLoginMutation } from '../../store/api/authApi';
import { setCredentials } from '../../store/slices/authSlice';
import { tokenStorage } from '../../utils/auth';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Alert, AlertDescription } from '../ui/Alert';
import { LoginCredentials } from '../../types';
import type { AppDispatch } from '../../store';

interface LoginFormProps {
  onSuccess?: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ onSuccess }) => {
  const [credentials, setCredentialsState] = useState<LoginCredentials>({
    username: '',
    password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useDispatch<AppDispatch>();
  
  const [login, { isLoading, error }] = useLoginMutation();

  // Get the intended destination from location state
  const from = (location.state as any)?.from?.pathname || '/dashboard';

  useEffect(() => {
    // Load saved credentials if remember me was checked
    const savedCredentials = localStorage.getItem('nms_remember_credentials');
    if (savedCredentials) {
      const parsed = JSON.parse(savedCredentials);
      setCredentialsState(parsed);
      setRememberMe(true);
    }
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setCredentialsState(prev => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const result = await login(credentials).unwrap();
      
      // Store tokens
      const tokens = {
        access: result.access,
        refresh: result.refresh,
      };
      tokenStorage.set(tokens);
      
      // Update Redux state
      dispatch(setCredentials({
        user: result.user,
        tokens,
      }));

      // Handle remember me
      if (rememberMe) {
        localStorage.setItem('nms_remember_credentials', JSON.stringify(credentials));
      } else {
        localStorage.removeItem('nms_remember_credentials');
      }

      // Call success callback or navigate
      if (onSuccess) {
        onSuccess();
      } else {
        navigate(from, { replace: true });
      }
    } catch (err) {
      console.error('Login failed:', err);
    }
  };

  const getErrorMessage = () => {
    if (!error) return null;
    
    if ('data' in error) {
      const errorData = error.data as any;
      if (errorData?.detail) {
        return errorData.detail;
      }
      if (errorData?.non_field_errors) {
        return errorData.non_field_errors[0];
      }
    }
    
    return 'Login failed. Please check your credentials and try again.';
  };

  return (
    <div className="login-container">
      <div className="login-form-wrapper">
        {/* WorldLink Branding */}
        <div className="login-branding">
          <div className="worldlink-logo w-20 h-20">
            <span className="text-white text-2xl font-bold">WL</span>
          </div>
          <h1 className="login-title">
            WorldLink NMS
          </h1>
          <p className="login-subtitle">
            Network Monitoring System
          </p>
        </div>

        <div className="login-card">
          <div className="login-card-header">
            <h2 className="login-card-title">Welcome Back</h2>
            <p className="login-card-description">
              Sign in to your account to continue
            </p>
          </div>
          
          <form onSubmit={handleSubmit} className="login-form">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>
                  {getErrorMessage()}
                </AlertDescription>
              </Alert>
            )}

            <div className="form-group">
              <label className="form-label">Username</label>
              <Input
                name="username"
                type="text"
                value={credentials.username}
                onChange={handleInputChange}
                placeholder="Enter your username"
                required
                autoComplete="username"
                disabled={isLoading}
                className={error ? 'error' : ''}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <div className="password-field">
                <Input
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={credentials.password}
                  onChange={handleInputChange}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                  disabled={isLoading}
                  className={error ? 'error' : ''}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isLoading}
                >
                  {showPassword ? (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
                    </svg>
                  ) : (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  )}
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
                  disabled={isLoading}
                />
                <span className="text-sm font-medium text-gray-700">Remember me</span>
              </label>
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={isLoading || !credentials.username || !credentials.password}
            >
              {isLoading ? (
                <div className="flex items-center space-x-2">
                  <div className="loading-spinner"></div>
                  <span>Signing in...</span>
                </div>
              ) : (
                'Sign In'
              )}
            </Button>

            {/* Default credentials hint for development */}
            {process.env.NODE_ENV === 'development' && (
              <div className="dev-hint">
                <p className="dev-hint-text">
                  <strong>Development Mode:</strong> Use admin / admin123
                </p>
              </div>
            )}
          </form>
        </div>

        {/* Footer */}
        <div className="login-footer">
          <p className="login-footer-text">
            &copy; 2025 WorldLink Communications. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
};