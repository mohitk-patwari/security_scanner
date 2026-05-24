import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { getStoredApiKey, login } from '../api'

export default function Login() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '' })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  function update(field) {
    return (e) => setForm((cur) => ({ ...cur, [field]: e.target.value }))
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      await login(form)
      // Login verifies password but doesn't return a key (bcrypt is one-way).
      // If user already has a key stored from signup, use that.
      // If not, they need to regenerate via Settings.
      const hasKey = !!getStoredApiKey()
      if (!hasKey) {
        setError('No API key stored. Sign up first, or regenerate your key from Settings after logging in.')
        setSubmitting(false)
        return
      }
      let next = '/'
      try {
        const stored = sessionStorage.getItem('netguard_post_login_redirect')
        if (stored) {
          sessionStorage.removeItem('netguard_post_login_redirect')
          next = stored
        }
      } catch { /* ignore */ }
      navigate(next, { replace: true })
    } catch (err) {
      setError(err.message || 'Login failed.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-shell">
      <form className="panel auth-card" onSubmit={handleSubmit}>
        <h2 style={{ marginTop: 0 }}>Welcome back</h2>
        <p className="subtle" style={{ marginBottom: '1rem' }}>
          Sign in to your NetGuard organization.
        </p>

        <label className="auth-label">Email</label>
        <input
          autoFocus
          type="email"
          value={form.email}
          onChange={update('email')}
          placeholder="you@company.com"
          autoComplete="email"
        />

        <label className="auth-label">Password</label>
        <input
          type="password"
          value={form.password}
          onChange={update('password')}
          autoComplete="current-password"
        />

        {error && (
          <div className="fix-error" style={{ marginTop: '0.5rem' }}>
            {error}
          </div>
        )}

        <button
          type="submit"
          className="btn"
          disabled={submitting}
          style={{ width: '100%', marginTop: '0.75rem' }}
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>

        <p className="subtle" style={{ marginTop: '0.75rem', fontSize: '0.85rem' }}>
          New here? <Link to="/signup" style={{ color: '#22d3ee' }}>Create an org</Link>
        </p>
        <p className="subtle" style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Login verifies your password but does not rotate your API key. Your key from signup remains valid until you regenerate it.
        </p>
      </form>
    </div>
  )
}
