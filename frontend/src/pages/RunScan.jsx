import { useEffect, useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { fetchMe, regenerateApiKey, setStoredApiKey } from '../api'

const WORKFLOW_PATH = '.github/workflows/netguard.yml'

function maskKey(key = '') {
  if (!key) return ''
  if (key.length <= 12) return key
  return `${key.slice(0, 8)}...${key.slice(-4)}`
}

function Info({ label, value }) {
  return (
    <div style={{ background: '#0d1527', border: '1px solid var(--border)', borderRadius: 10, padding: '0.55rem 0.65rem' }}>
      <div style={{ color: 'var(--text-subtle)', fontSize: '0.75rem', marginBottom: 2 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600, wordBreak: 'break-all' }}>{value}</div>
    </div>
  )
}

export default function RunScan() {
  const [settings, setSettings] = useState(null)
  const [repoName, setRepoName] = useState('')
  const [showApiKey, setShowApiKey] = useState(false)
  const [loading, setLoading] = useState(true)
  const [regenerating, setRegenerating] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  async function loadSession() {
    setLoading(true)
    setError('')
    try {
      // Use GET /api/me (same payload as /api/settings) so the guide works even if
      // an older proxy or deployment omitted the dedicated settings route.
      const data = await fetchMe()
      setSettings(data)
    } catch (err) {
      setError(err.message || 'Failed to load settings.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setError('')
      try {
        const data = await fetchMe()
        if (!cancelled) setSettings(data)
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load settings.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const displayApiKey = useMemo(() => {
    if (!settings?.api_key) return ''
    return showApiKey ? settings.api_key : (settings.api_key_masked || maskKey(settings.api_key))
  }, [settings, showApiKey])

  async function handleCopy(text, label) {
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setNotice(`${label} copied.`)
      setTimeout(() => setNotice(''), 2000)
    } catch {
      setNotice(`Could not copy ${label.toLowerCase()}.`)
    }
  }

  async function handleRegenerate() {
    setNotice('')
    setError('')
    setRegenerating(true)
    try {
      const data = await regenerateApiKey()
      if (data?.api_key) setStoredApiKey(data.api_key)
      await loadSession()
      setNotice(data?.message || 'API key regenerated.')
    } catch (err) {
      setError(err.message || 'Failed to regenerate API key.')
    } finally {
      setRegenerating(false)
    }
  }

  return (
    <div className="page" style={{ maxWidth: 920, margin: '0 auto' }}>
      <div className="page-header">
        <div>
          <h2 className="page-title">PR Scan Guide</h2>
          <p className="subtle">Configure any GitHub repository for automatic NetGuard IaC scanning.</p>
        </div>
      </div>

      {loading && <div className="panel">Loading settings…</div>}
      {!loading && error && (
        <div className="fix-error">
          {error}
          {/Not Found/i.test(error) ? (
            <p className="subtle" style={{ margin: '0.75rem 0 0' }}>
              Restart the NetGuard API with the latest code. For local dev, set{' '}
              <code>VITE_API_BASE_URL=http://localhost:8000</code> in <code>frontend/.env</code>.
              On Vercel, API calls use same-origin <code>/api/*</code> via <code>vercel.json</code> rewrites.
            </p>
          ) : null}
        </div>
      )}
      {!loading && notice && <div className="fix-success">{notice}</div>}

      {!loading && settings && (
        <>
          {/* Organization Info */}
          <section className="panel card-elevated fade-in" style={{ marginBottom: '1rem' }}>
            <h3 style={{ marginTop: 0 }}>Organization</h3>
            <div className="section-grid">
              <Info label="Organization" value={settings.org_name || '-'} />
              <Info label="User email" value={settings.user_email || '-'} />
            </div>
          </section>

          {/* API Key Section */}
          <section className="panel card-elevated fade-in" style={{ marginBottom: '1rem' }}>
            <h3 style={{ marginTop: 0 }}>API Key</h3>
            <p className="subtle" style={{ marginTop: 0 }}>
              This key does not rotate on login. Use it as <code>NETGUARD_API_KEY</code> in GitHub Actions secrets.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '0.6rem', alignItems: 'center' }}>
              <input
                readOnly
                value={displayApiKey}
                style={{ fontFamily: 'SF Mono, Monaco, Consolas, monospace' }}
              />
              <button type="button" className="btn btn-ghost" onClick={() => setShowApiKey((v) => !v)}>
                {showApiKey ? 'Hide' : 'Show'}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => handleCopy(settings.api_key, 'API key')}>
                Copy Key
              </button>
            </div>
            <div style={{ display: 'flex', gap: '0.6rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
              <button type="button" className="btn" disabled={regenerating} onClick={handleRegenerate}>
                {regenerating ? 'Regenerating…' : 'Regenerate Key'}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => handleCopy(settings.hmac_secret, 'HMAC secret')}>
                Copy NETGUARD_SECRET
              </button>
            </div>
            <p className="subtle" style={{ marginBottom: 0, marginTop: '0.6rem' }}>
              If you regenerate, update <code>NETGUARD_API_KEY</code> in all your GitHub repo secrets. You can also manage this on{' '}
              <Link to="/settings" style={{ color: '#22d3ee' }}>Settings</Link>.
            </p>
          </section>

          {/* Add Repository Section */}
          <section className="panel card-elevated fade-in" style={{ marginBottom: '1rem' }}>
            <h3 style={{ marginTop: 0 }}>Add Repository</h3>
            <p className="subtle" style={{ marginTop: 0 }}>
              Enter a GitHub repository as <code>owner/repo</code> to generate setup instructions.
            </p>
            <label className="auth-label">GitHub repo (e.g., owner/repo)</label>
            <input
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder="owner/repo"
              autoComplete="off"
            />

            {repoName.trim() && (
              <div style={{ marginTop: '1rem', padding: '1rem', background: '#0d1527', borderRadius: 10, border: '1px solid var(--border)' }}>
                <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.95rem', color: '#4ade80' }}>Setup Instructions for {repoName.trim()}</h4>
                <ol style={{ margin: 0, paddingLeft: '1.25rem', lineHeight: 1.9, color: '#cbd5e1' }}>
                  <li>
                    Copy <code style={{ color: '#22d3ee' }}>{WORKFLOW_PATH}</code> to your repo.
                  </li>
                  <li>
                    Add these secrets to <strong>{repoName.trim()}</strong>:
                    <ul style={{ marginTop: '0.5rem', listStyle: 'none', paddingLeft: 0 }}>
                      <li style={{ marginBottom: '0.4rem' }}>
                        <code style={{ color: '#22d3ee' }}>NETGUARD_API_URL</code> = <code>{settings.api_url}</code>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ marginLeft: '0.5rem', padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => handleCopy(settings.api_url, 'API URL')}
                        >
                          Copy
                        </button>
                      </li>
                      <li style={{ marginBottom: '0.4rem' }}>
                        <code style={{ color: '#22d3ee' }}>NETGUARD_SECRET</code> = <code>{settings.hmac_secret?.slice(0, 12)}...</code>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ marginLeft: '0.5rem', padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => handleCopy(settings.hmac_secret, 'HMAC secret')}
                        >
                          Copy
                        </button>
                      </li>
                      <li style={{ marginBottom: '0.4rem' }}>
                        <code style={{ color: '#22d3ee' }}>NETGUARD_API_KEY</code> = <code>{settings.api_key_masked}</code>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ marginLeft: '0.5rem', padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => handleCopy(settings.api_key, 'API key')}
                        >
                          Copy
                        </button>
                      </li>
                    </ul>
                  </li>
                  <li>Open a PR to trigger scanning.</li>
                </ol>
              </div>
            )}
          </section>

          {/* How it works */}
          <section className="panel card-elevated fade-in">
            <h3 style={{ marginTop: 0 }}>How it works</h3>
            <ol style={{ margin: 0, paddingLeft: '1.25rem', color: '#94a3b8', lineHeight: 1.85, fontSize: '0.92rem' }}>
              <li>When a PR is created or updated, the workflow runs automatically.</li>
              <li>NetGuard scans all <code style={{ color: '#22d3ee' }}>.tf</code>, <code style={{ color: '#22d3ee' }}>.yaml</code>, and <code style={{ color: '#22d3ee' }}>.yml</code> files in the branch.</li>
              <li>Results appear as a PR comment with findings and severity.</li>
              <li>View detailed results in <Link to="/" style={{ color: '#0ea5e9' }}>Dashboard</Link> and <Link to="/scans" style={{ color: '#0ea5e9' }}>Scan History</Link>.</li>
              <li>PRs with CRITICAL/HIGH findings are blocked from merging until resolved.</li>
            </ol>
          </section>
        </>
      )}
    </div>
  )
}
