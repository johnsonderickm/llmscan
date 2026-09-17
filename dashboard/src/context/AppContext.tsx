import React, { createContext, useContext, useReducer } from 'react'
import type { Audience, Finding, Plugin, Scan } from '../types'

type Theme = 'light' | 'dark'

const THEME_KEY = 'llmscan-theme'

function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // localStorage unavailable (private window, blocked storage, etc.)
  }
  return 'light'
}

function persistTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_KEY, theme)
  } catch {
    // best-effort only — theme just won't persist this session
  }
}

interface AppState {
  theme: Theme
  audience: Audience
  scans: Scan[]
  activeScanId: string | null
  findings: Finding[]
  plugins: Plugin[]
}

type Action =
  | { type: 'SET_THEME'; payload: Theme }
  | { type: 'SET_AUDIENCE'; payload: Audience }
  | { type: 'SET_SCANS'; payload: Scan[] }
  | { type: 'ADD_SCAN'; payload: Scan }
  | { type: 'UPDATE_SCAN'; payload: Scan }
  | { type: 'SET_ACTIVE_SCAN'; payload: string | null }
  | { type: 'SET_FINDINGS'; payload: Finding[] }
  | { type: 'SET_PLUGINS'; payload: Plugin[] }

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'SET_THEME':
      document.documentElement.setAttribute('data-theme', action.payload)
      persistTheme(action.payload)
      return { ...state, theme: action.payload }
    case 'SET_AUDIENCE':
      return { ...state, audience: action.payload }
    case 'SET_SCANS':
      return { ...state, scans: action.payload }
    case 'ADD_SCAN':
      return { ...state, scans: [action.payload, ...state.scans] }
    case 'UPDATE_SCAN':
      return {
        ...state,
        scans: state.scans.map(s => s.id === action.payload.id ? action.payload : s),
      }
    case 'SET_ACTIVE_SCAN':
      return { ...state, activeScanId: action.payload }
    case 'SET_FINDINGS':
      return { ...state, findings: action.payload }
    case 'SET_PLUGINS':
      return { ...state, plugins: action.payload }
    default:
      return state
  }
}

const initialTheme = getStoredTheme()
document.documentElement.setAttribute('data-theme', initialTheme)

const initialState: AppState = {
  theme: initialTheme,
  audience: 'pentester',
  scans: [],
  activeScanId: null,
  findings: [],
  plugins: [],
}

interface AppContextValue {
  state: AppState
  dispatch: React.Dispatch<Action>
}

const AppContext = createContext<AppContextValue | null>(null)

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState)
  return <AppContext.Provider value={{ state, dispatch }}>{children}</AppContext.Provider>
}

export function useApp() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used inside AppProvider')
  return ctx
}
