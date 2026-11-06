export default function Badge({
  variant = 'neutral',
  icon: Icon,
  children,
  className = '',
  style = {},
}) {
  return (
    <span className={`ui-badge ui-badge-${variant} ${className}`} style={style}>
      {Icon && <Icon size={12} />}
      {children}
    </span>
  );
}
