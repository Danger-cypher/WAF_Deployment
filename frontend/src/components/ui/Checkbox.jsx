import { forwardRef, useRef, useEffect } from 'react';
import { Check, Minus } from 'lucide-react';

const Checkbox = forwardRef(function Checkbox({
  checked = false,
  indeterminate = false,
  onChange,
  disabled = false,
  label,
  description,
  id,
  name,
  className = '',
  ...rest
}, ref) {
  const innerRef = useRef(null);
  const resolvedRef = ref || innerRef;

  useEffect(() => {
    if (resolvedRef.current) {
      resolvedRef.current.indeterminate = Boolean(indeterminate);
    }
  }, [indeterminate, resolvedRef]);

  const handleChange = (e) => {
    if (disabled) return;
    onChange?.(e);
  };

  const isChecked = Boolean(checked) && !indeterminate;

  return (
    <label
      htmlFor={id}
      className={`ui-checkbox-wrapper ${disabled ? 'disabled' : ''} ${className}`}
    >
      <input
        ref={resolvedRef}
        type="checkbox"
        id={id}
        name={name}
        checked={isChecked}
        disabled={disabled}
        onChange={handleChange}
        className="ui-checkbox-input-hidden"
        aria-checked={indeterminate ? 'mixed' : isChecked}
        {...rest}
      />
      <div
        className={`ui-checkbox-box ${isChecked ? 'checked' : ''} ${indeterminate ? 'indeterminate' : ''}`}
        aria-hidden="true"
      >
        {isChecked && <Check size={12} strokeWidth={3} />}
        {indeterminate && <Minus size={12} strokeWidth={3} />}
      </div>
      {(label || description) && (
        <div className="ui-checkbox-content">
          {label && <span className="ui-checkbox-label">{label}</span>}
          {description && <span className="ui-checkbox-description">{description}</span>}
        </div>
      )}
    </label>
  );
});

export default Checkbox;
