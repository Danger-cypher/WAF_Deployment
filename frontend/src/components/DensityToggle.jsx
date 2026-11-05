import { LayoutGrid, Rows } from 'lucide-react';
import { useDensity } from '../hooks/useDensity';

export default function DensityToggle() {
  const { density, setDensity } = useDensity();

  return (
    <div
      role="group"
      aria-label="Display density"
      className="density-toggle-group"
      title={`Current display density: ${density}. Click to switch between Comfortable and Compact triage views.`}
    >
      <button
        type="button"
        aria-pressed={density === 'comfortable'}
        onClick={() => setDensity('comfortable')}
        className={`density-toggle-btn ${density === 'comfortable' ? 'active' : ''}`}
        title="Comfortable density (relaxed spacing, executive view)"
      >
        <LayoutGrid size={13} aria-hidden="true" />
        <span className="density-toggle-label">Comfortable</span>
      </button>

      <button
        type="button"
        aria-pressed={density === 'compact'}
        onClick={() => setDensity('compact')}
        className={`density-toggle-btn ${density === 'compact' ? 'active' : ''}`}
        title="Compact density (dense data triage, higher rows visible)"
      >
        <Rows size={13} aria-hidden="true" />
        <span className="density-toggle-label">Compact</span>
      </button>
    </div>
  );
}
