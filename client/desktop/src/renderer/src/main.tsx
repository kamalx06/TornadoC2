import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import ErrorBoundary from './ui/ErrorBoundary'
import './styles/tokens.css'
import './styles/foundation.css'
import './styles/dock.css'
import './styles/app.css'

const storedTheme = localStorage.getItem('t2:theme')
const storedDensity = localStorage.getItem('t2:density')
document.documentElement.dataset.theme = storedTheme === 'light' ? 'light' : 'dark'
document.documentElement.dataset.density =
  storedDensity === 'cozy' || storedDensity === 'dense' ? storedDensity : 'compact'

async function boot(): Promise<void> {
  // Detached windows can race their preload registration on first paint.
  for (let i = 0; i < 60 && !window.t2; i++) {
    await new Promise((r) => setTimeout(r, 50))
  }
  createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </React.StrictMode>
  )
}

void boot()
