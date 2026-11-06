import { forwardRef } from 'react';

const Switch = forwardRef(function Switch({
  checked = false,
  onChange,
  disabled = false,
  label,
  description,
  id,
  className = '',
  ...rest
}, ref) {
  const handleClick = (e) => {
    if (disabled) return;
    onChange?.(!checked, e);
  };

  const handleKeyDown = (e) => {
    if (disabled) return;
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      onChange?.(!checked, e);
    }
  };

  return (
    <div
      className={`ui-switch-wrapper ${className}`}
      style={{ display: 'inline-flex', alignItems: 'flex-start', gap: '10px', cursor: disabled ? 'not-allowed' : 'pointer' }}
      onClick={handleClick}
    >
      <button
        ref={ref}
        type="button"
        role="switch"
        id={id}
        aria-checked={Boolean(checked)}
        disabled={disabled}
        className={`toggle-switch ${checked ? 'active' : ''}`}
        onKeyDown={handleKeyDown}
        onClick={(e) => {
          e.stopPropagation();
          handleClick(e);
        }}
        {...rest}
      >
        <span className="toggle-knob" />
      </button>

      {(label || description) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', userSelect: 'none' }}>
          {label && (
            <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)', lineHeight: 1.4 }}>
              {label}
            </span>
          )}
          {description && (
            <span style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              {description}
            </span>
          )}
        </div>
      )}
    </div>
  );
});

export default Switch;
