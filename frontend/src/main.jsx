import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { ThemeProvider } from './context/ThemeContext.jsx'
import { ConfirmProvider } from './context/ConfirmContext.jsx'

// Applied synchronously, before first paint, so the correct theme is present
// from frame one — ThemeProvider's effect would otherwise run a tick late
// and cause a visible flash of the wrong theme on load.
(function applyInitialTheme() {
  let mode = 'dark';
  try {
    const stored = localStorage.getItem('cybersentinel-theme');
    if (stored === 'dark' || stored === 'light' || stored === 'system') mode = stored;
  } catch {
    // localStorage unavailable — fall back to default dark theme
  }
  const resolved = mode === 'system'
    ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    : mode;
  document.documentElement.setAttribute('data-theme', resolved);
})();

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <ConfirmProvider>
        <App />
      </ConfirmProvider>
    </ThemeProvider>
  </StrictMode>,
)
