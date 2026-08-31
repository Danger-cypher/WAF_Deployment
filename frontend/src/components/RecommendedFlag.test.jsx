import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import RecommendedFlag from './RecommendedFlag';
import { RECOMMENDED_BASELINE } from '../utils/recommendedBaseline';

describe('RecommendedFlag', () => {
  it('renders nothing when the current value already matches the recommendation', () => {
    const { container } = render(<RecommendedFlag current="On" recommended="On" />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders the recommendation when the current value differs', () => {
    render(<RecommendedFlag current="Off" recommended="On" label="On" />);
    expect(screen.getByText(/Recommended: On/)).toBeInTheDocument();
  });

  it('falls back to stringifying `recommended` when no label is given', () => {
    render(<RecommendedFlag current={false} recommended={true} />);
    expect(screen.getByText(/Recommended: true/)).toBeInTheDocument();
  });

  it('distinguishes boolean false from a falsy-but-different value (strict equality, not loose)', () => {
    // Regression guard: `current === recommended` must be strict — a loose
    // `==` would treat 0/false/"" as all interchangeable and hide real drift.
    render(<RecommendedFlag current={0} recommended={false} label="On" />);
    expect(screen.getByText(/Recommended: On/)).toBeInTheDocument();
  });
});

describe('RECOMMENDED_BASELINE', () => {
  it('only covers settings with no real operational downside to recommending on', () => {
    // Documents the deliberate scope (see RecommendedFlag.jsx's docstring)
    // — settings that are legitimately off-by-default for good reasons
    // (admin IP allowlist, geo-block, positive security, auto-learning)
    // must never end up in here as a blanket "should be on" recommendation.
    const flatKeys = Object.values(RECOMMENDED_BASELINE).flatMap((section) => Object.keys(section));
    expect(flatKeys).toEqual(['secRuleEngine', 'detectionMode', 'auditEnabled', 'hsts_enabled', 'server_cloaking']);
  });
});
