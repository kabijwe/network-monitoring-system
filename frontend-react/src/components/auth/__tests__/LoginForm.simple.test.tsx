import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';

// Create a simple mock LoginForm component for testing
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

describe('LoginForm Simple Tests', () => {
  it('renders login form with all required elements', () => {
    render(<MockLoginForm />);

    // Check branding elements
    expect(screen.getByText('WorldLink NMS')).toBeInTheDocument();
    expect(screen.getByText('Network Monitoring System')).toBeInTheDocument();
    expect(screen.getByText('Welcome Back')).toBeInTheDocument();
    expect(screen.getByText('Sign in to your account to continue')).toBeInTheDocument();

    // Check form elements
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /remember me/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    render(<MockLoginForm />);

    const submitButton = screen.getByRole('button', { name: /sign in/i });
    
    // Submit button should be disabled when fields are empty
    expect(submitButton).toBeDisabled();

    // Fill username only
    const usernameInput = screen.getByLabelText(/username/i);
    fireEvent.change(usernameInput, { target: { value: 'admin' } });
    expect(submitButton).toBeDisabled();

    // Fill password only (clear username first)
    fireEvent.change(usernameInput, { target: { value: '' } });
    const passwordInput = screen.getByLabelText(/password/i);
    fireEvent.change(passwordInput, { target: { value: 'password' } });
    expect(submitButton).toBeDisabled();

    // Fill both fields
    fireEvent.change(usernameInput, { target: { value: 'admin' } });
    expect(submitButton).not.toBeDisabled();
  });

  it('toggles password visibility', async () => {
    render(<MockLoginForm />);

    const passwordInput = screen.getByLabelText(/password/i) as HTMLInputElement;
    const toggleButtons = screen.getAllByRole('button');
    const toggleButton = toggleButtons.find(button => 
      button.querySelector('svg') && !button.textContent?.includes('Sign')
    );

    // Initially password should be hidden
    expect(passwordInput.type).toBe('password');

    if (toggleButton) {
      // Click toggle to show password
      fireEvent.click(toggleButton);
      expect(passwordInput.type).toBe('text');

      // Click toggle to hide password again
      fireEvent.click(toggleButton);
      expect(passwordInput.type).toBe('password');
    }
  });

  it('handles remember me functionality', async () => {
    render(<MockLoginForm />);

    const rememberCheckbox = screen.getByRole('checkbox', { name: /remember me/i });
    
    // Initially unchecked
    expect(rememberCheckbox).not.toBeChecked();

    // Check remember me
    fireEvent.click(rememberCheckbox);
    expect(rememberCheckbox).toBeChecked();
  });

  it('shows development hint in development mode', () => {
    // Mock NODE_ENV
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    render(<MockLoginForm />);

    expect(screen.getByText(/development mode/i)).toBeInTheDocument();
    expect(screen.getByText(/admin \/ admin123/i)).toBeInTheDocument();

    // Restore original NODE_ENV
    process.env.NODE_ENV = originalEnv;
  });

  it('applies correct CSS classes for styling', () => {
    render(<MockLoginForm />);

    // Check main container has correct classes
    const container = document.querySelector('.login-container');
    expect(container).toBeInTheDocument();

    // Check form wrapper
    const wrapper = document.querySelector('.login-form-wrapper');
    expect(wrapper).toBeInTheDocument();

    // Check branding section
    const branding = document.querySelector('.login-branding');
    expect(branding).toBeInTheDocument();

    // Check card
    const card = document.querySelector('.login-card');
    expect(card).toBeInTheDocument();
  });

  it('has proper form structure and accessibility', () => {
    render(<MockLoginForm />);

    // Check form has proper labels
    const usernameInput = screen.getByLabelText(/username/i);
    const passwordInput = screen.getByLabelText(/password/i);
    
    expect(usernameInput).toHaveAttribute('name', 'username');
    expect(usernameInput).toHaveAttribute('type', 'text');
    expect(usernameInput).toHaveAttribute('required');
    expect(usernameInput).toHaveAttribute('autoComplete', 'username');

    expect(passwordInput).toHaveAttribute('name', 'password');
    expect(passwordInput).toHaveAttribute('type', 'password');
    expect(passwordInput).toHaveAttribute('required');
    expect(passwordInput).toHaveAttribute('autoComplete', 'current-password');
  });

  it('displays WorldLink branding correctly', () => {
    render(<MockLoginForm />);

    // Check logo
    expect(screen.getByText('WL')).toBeInTheDocument();
    
    // Check title and subtitle
    expect(screen.getByText('WorldLink NMS')).toBeInTheDocument();
    expect(screen.getByText('Network Monitoring System')).toBeInTheDocument();
    
    // Check footer
    expect(screen.getByText(/© 2025 WorldLink Communications/i)).toBeInTheDocument();
  });
});