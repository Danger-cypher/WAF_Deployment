import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DensityProvider } from '../context/DensityContext';
import DensityToggle from './DensityToggle';

describe('DensityToggle & DensityContext', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-density');
  });

  it('renders both Comfortable and Compact density options', () => {
    render(
      <DensityProvider>
        <DensityToggle />
      </DensityProvider>
    );

    expect(screen.getByRole('button', { name: /comfortable/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /compact/i })).toBeInTheDocument();
  });

  it('defaults to comfortable density and sets data-density attribute', () => {
    render(
      <DensityProvider>
        <DensityToggle />
      </DensityProvider>
    );

    const comfortableBtn = screen.getByRole('button', { name: /comfortable/i });
    expect(comfortableBtn).toHaveAttribute('aria-pressed', 'true');
    expect(document.documentElement.getAttribute('data-density')).toBe('comfortable');
  });

  it('switches to compact density when clicked and updates localStorage and DOM', async () => {
    const user = userEvent.setup();
    render(
      <DensityProvider>
        <DensityToggle />
      </DensityProvider>
    );

    const compactBtn = screen.getByRole('button', { name: /compact/i });
    await user.click(compactBtn);

    expect(compactBtn).toHaveAttribute('aria-pressed', 'true');
    expect(document.documentElement.getAttribute('data-density')).toBe('compact');
    expect(localStorage.getItem('cybersentinel-density')).toBe('compact');
  });

  it('restores stored density from localStorage on mount', () => {
    localStorage.setItem('cybersentinel-density', 'compact');
    render(
      <DensityProvider>
        <DensityToggle />
      </DensityProvider>
    );

    const compactBtn = screen.getByRole('button', { name: /compact/i });
    expect(compactBtn).toHaveAttribute('aria-pressed', 'true');
    expect(document.documentElement.getAttribute('data-density')).toBe('compact');
  });
});
