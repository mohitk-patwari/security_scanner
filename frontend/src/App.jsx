import { useEffect, useState } from 'react'
import { Routes, Route, NavLink, useLocation, Navigate, useNavigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import ScanHistory from './pages/ScanHistory'
import ScanDetail from './pages/ScanDetail'
import ScanGraph from './pages/ScanGraph'
import RunScan from './pages/RunScan'
import Settings from './pages/Settings'
import Signup from './pages/Signup'
import Login from './pages/Login'
import { clearStoredApiKey, fetchMe, getStoredApiKey } from './api'
import './App.css'

function ProtectedRoute({ children }) {
  const apiKey = getStoredApiKey()
  if (!apiKey) {
    return <Navigate to="/login" replace />
  }
  return children
}

function PublicOnlyRoute({ children }) {
  const apiKey = getStoredApiKey()
  if (apiKey) return <Navigate to="/" replace />
  return children
}

function ProtectedLayout() {
  const navigate = useNavigate()
  const [me, setMe] = useState(null)
  const [meError, setMeError] = useState(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const data = await fetchMe()
        if (!cancelled) {
          setMe(data)
          setMeError(null)
        }
      } catch (err) {
        if (!cancelled) setMeError(err)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  function handleLogout() {
    clearStoredApiKey()
    navigate('/login', { replace: true })
  }

  return (
    <div className="layout">
      <header className="header">
        <div className="header-left">
          <h1 className="logo">NetGuard</h1>
          {me?.org_name && (
            <span className="org-pill" title={me.user_email || ''}>
              {me.org_name}
            </span>
          )}
        </div>
        <nav className="nav">
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/scans">Scan History</NavLink>
          <NavLink to="/run">PR Scan Guide</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
        <div className="header-right">
          {me?.user_email && <span className="user-email">{me.user_email}</span>}
          <button type="button" className="btn btn-ghost" onClick={handleLogout}>
            Log out
          </button>
        </div>
      </header>
      <main className="main">
        <div className="fade-in">
          {meError && (
            <div className="fix-error" style={{ marginBottom: '1rem' }}>
              Could not load your organization info. Try refreshing or signing in again.
            </div>
          )}
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans" element={<ScanHistory />} />
            <Route path="/scans/:scanId" element={<ScanDetail />} />
            <Route path="/scans/:scanId/graph" element={<ScanGraph />} />
            <Route path="/run" element={<RunScan />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

function App() {
  const location = useLocation()
  return (
    <div key={location.pathname}>
      <Routes location={location}>
        <Route
          path="/signup"
          element={
            <PublicOnlyRoute>
              <Signup />
            </PublicOnlyRoute>
          }
        />
        <Route
          path="/login"
          element={
            <PublicOnlyRoute>
              <Login />
            </PublicOnlyRoute>
          }
        />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <ProtectedLayout />
            </ProtectedRoute>
          }
        />
      </Routes>
    </div>
  )
}

export default App
