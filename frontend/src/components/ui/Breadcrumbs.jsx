import { ChevronRight } from 'lucide-react';

export default function Breadcrumbs({ items = [], className = '' }) {
  if (!items || items.length === 0) return null;

  return (
    <nav aria-label="Breadcrumb" className={`ui-breadcrumbs ${className}`}>
      <ol style={{ display: 'flex', alignItems: 'center', gap: '6px', listStyle: 'none', margin: 0, padding: 0 }}>
        {items.map((item, index) => {
          const isLast = index === items.length - 1 || item.active;
          const Icon = item.icon;

          return (
            <li key={index} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              {index > 0 && (
                <ChevronRight size={13} className="ui-breadcrumb-separator" aria-hidden="true" />
              )}
              {isLast ? (
                <span className="ui-breadcrumb-item active" aria-current="page">
                  {Icon && <Icon size={13} />}
                  <span>{item.label}</span>
                </span>
              ) : item.onClick ? (
                <button
                  type="button"
                  className="ui-breadcrumb-item"
                  onClick={item.onClick}
                  style={{ background: 'none', border: 'none', padding: 0, font: 'inherit' }}
                >
                  {Icon && <Icon size={13} />}
                  <span>{item.label}</span>
                </button>
              ) : (
                <span className="ui-breadcrumb-item">
                  {Icon && <Icon size={13} />}
                  <span>{item.label}</span>
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
