import { forwardRef } from 'react';
import { Loader2 } from 'lucide-react';

const Button = forwardRef(function Button({
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  loading = false,
  disabled = false,
  children,
  className = '',
  type = 'button',
  ...rest
}, ref) {
  const classes = ['btn', `btn-${variant}`, `btn-${size}`, className].filter(Boolean).join(' ');

  return (
    <button ref={ref} type={type} className={classes} disabled={disabled || loading} {...rest}>
      {loading ? <Loader2 size={size === 'sm' ? 14 : 16} className="animate-spin" /> : Icon && <Icon size={size === 'sm' ? 14 : 16} />}
      {children && <span>{children}</span>}
    </button>
  );
});

export default Button;
