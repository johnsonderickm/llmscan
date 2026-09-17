import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { AudienceToggle } from './components/AudienceToggle'
import { AppProvider, useApp } from './context/AppContext'
import { FindingExplorer } from './pages/FindingExplorer'
import { ScanHistory } from './pages/ScanHistory'
import { ScanLive } from './pages/ScanLive'
import { ScanSetup } from './pages/ScanSetup'

function ThemeToggle() {
  const { state, dispatch } = useApp()
  const isDark = state.theme === 'dark'
  return (
    <button
      onClick={() => dispatch({ type: 'SET_THEME', payload: isDark ? 'light' : 'dark' })}
      className="w-8 h-8 rounded-lg flex items-center justify-center text-base transition-colors"
      style={{ background: 'var(--color-bg)', color: 'var(--color-text)' }}
      title="Toggle theme"
    >
      {isDark ? '☀️' : '🌙'}
    </button>
  )
}

function Nav() {
  const { pathname } = useLocation()
  const links = [
    { to: '/', label: 'New scan' },
    { to: '/history', label: 'History' },
  ]
  return (
    <header className="border-b" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center gap-6">
        <span className="font-bold text-sm tracking-tight" style={{ color: 'var(--color-text)' }}>
          🔍 LLMScan
        </span>
        <nav className="flex gap-4 flex-1">
          {links.map(l => (
            <Link
              key={l.to}
              to={l.to}
              className="text-sm font-medium transition-colors"
              style={{ color: pathname === l.to ? 'var(--color-accent)' : 'var(--color-muted)' }}
            >
              {l.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-3">
          <AudienceToggle />
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}

function Layout() {
  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>
      <Nav />
      <main className="px-4 pb-16">
        <Routes>
          <Route path="/" element={<ScanSetup />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/scans/:scanId/live" element={<ScanLive />} />
          <Route path="/scans/:scanId/findings" element={<FindingExplorer />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <AppProvider>
      <BrowserRouter>
        <Layout />
      </BrowserRouter>
    </AppProvider>
  )
}
