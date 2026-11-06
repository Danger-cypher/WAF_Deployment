import { forwardRef } from 'react';

const TextInput = forwardRef(function TextInput({
  id,
  type = 'text',
  value,
  onChange,
  onBlur,
  placeholder,
  disabled = false,
  error = false,
  iconPrefix: IconPrefix,
  iconSuffix: iconSuffix,
  className = '',
  ...rest
}, ref) {
  const hasPrefix = Boolean(IconPrefix);
  const hasSuffix = Boolean(iconSuffix);

  return (
    <div className="ui-input-wrapper">
      {hasPrefix && (
        <span className="ui-input-icon-prefix">
          <IconPrefix size={16} />
        </span>
      )}

      <input
        ref={ref}
        id={id}
        type={type}
        value={value}
        onChange={onChange}
        onBlur={onBlur}
        placeholder={placeholder}
        disabled={disabled}
        aria-invalid={error ? 'true' : 'false'}
        aria-describedby={error && id ? `${id}-error` : undefined}
        className={`ui-input ${hasPrefix ? 'has-prefix' : ''} ${hasSuffix ? 'has-suffix' : ''} ${error ? 'error' : ''} ${className}`}
        {...rest}
      />

      {hasSuffix && (
        <span className="ui-input-icon-suffix">
          {iconSuffix}
        </span>
      )}
    </div>
  );
});

export default TextInput;
