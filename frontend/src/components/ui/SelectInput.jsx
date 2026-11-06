import { forwardRef } from 'react';
import { ChevronDown } from 'lucide-react';

const SelectInput = forwardRef(function SelectInput({
  id,
  value,
  onChange,
  onBlur,
  disabled = false,
  error = false,
  children,
  className = '',
  ...rest
}, ref) {
  return (
    <div className="ui-input-wrapper">
      <select
        ref={ref}
        id={id}
        value={value}
        onChange={onChange}
        onBlur={onBlur}
        disabled={disabled}
        aria-invalid={error ? 'true' : 'false'}
        aria-describedby={error && id ? `${id}-error` : undefined}
        className={`ui-select ${error ? 'error' : ''} ${className}`}
        {...rest}
      >
        {children}
      </select>
      <span
        style={{
          position: 'absolute',
          right: '12px',
          top: '50%',
          transform: 'translateY(-50%)',
          pointerEvents: 'none',
          color: 'var(--text-muted)',
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <ChevronDown size={15} />
      </span>
    </div>
  );
});

export default SelectInput;
