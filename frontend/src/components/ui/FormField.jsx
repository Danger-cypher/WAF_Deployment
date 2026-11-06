import { AlertCircle } from 'lucide-react';

export default function FormField({
  label,
  id,
  required = false,
  optional = false,
  hint,
  error,
  children,
  className = '',
  style = {},
}) {
  return (
    <div className={`ui-form-field ${className}`} style={style}>
      {label && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <label htmlFor={id} className="ui-label">
            {label}
          </label>
          {required && <span className="ui-required-mark" aria-hidden="true">*</span>}
          {optional && <span className="ui-optional-mark">(Optional)</span>}
        </div>
      )}

      {children}

      {hint && !error && <span className="ui-field-hint">{hint}</span>}

      {error && (
        <div className="ui-field-error" role="alert" id={id ? `${id}-error` : undefined}>
          <AlertCircle size={13} />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
