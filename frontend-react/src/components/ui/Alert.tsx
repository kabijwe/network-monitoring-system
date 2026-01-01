import React from 'react';

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'destructive' | 'warning' | 'success' | 'info';
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ className = '', variant = 'default', ...props }, ref) => {
    const variantClasses = {
      default: 'alert',
      destructive: 'alert alert-destructive',
      warning: 'alert alert-warning',
      success: 'alert alert-success',
      info: 'alert alert-info',
    };

    return (
      <div
        ref={ref}
        role="alert"
        className={`${variantClasses[variant]} ${className}`.trim()}
        {...props}
      />
    );
  }
);
Alert.displayName = 'Alert';

const AlertTitle = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className = '', ...props }, ref) => (
  <h5
    ref={ref}
    className={`mb-1 font-medium ${className}`.trim()}
    {...props}
  />
));
AlertTitle.displayName = 'AlertTitle';

const AlertDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className = '', ...props }, ref) => (
  <div
    ref={ref}
    className={`text-sm ${className}`.trim()}
    {...props}
  />
));
AlertDescription.displayName = 'AlertDescription';

export { Alert, AlertTitle, AlertDescription };