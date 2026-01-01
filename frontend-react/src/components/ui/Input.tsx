import React from 'react';

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className = '', type, label, error, helperText, ...props }, ref) => {
    return (
      <div>
        {label && (
          <label className="form-label">
            {label}
          </label>
        )}
        <input
          type={type}
          className={`input ${error ? 'error' : ''} ${className}`.trim()}
          ref={ref}
          {...props}
        />
        {error && (
          <p className="text-sm text-red-600 mt-1">{error}</p>
        )}
        {helperText && !error && (
          <p className="text-sm text-gray-500 mt-1">{helperText}</p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

export { Input };