import { useEffect, useMemo, useState } from 'react'
import { fetchMe, regenerateApiKey, setStoredApiKey } from '../api'

const WORKFLOW_PATH = '.github/workflows/netguard.yml'

function maskLocalKey(key = '') {
  if (!key) return ''
  if (key.length <= 12) return key
  return `${key.slice(0, 8)}...${key.slice(-4)}`
}

export default function Settings() {
  const [settings, setSettings] = useState(null)
  const [repoName, setRepoName] = useState('')
  const [showApiKey, setShowApiKey] = useState(false)
  const [loading, setLoading] = useState(true)
  const [regenerating, setRegenerating] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  async function loadSettings() {
    setLoading(true)
    setError('')
    try {
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
    return showApiKey ? settings.api_key : (settings.api_key_masked || maskLocalKey(settings.api_key))
  }, [settings, showApiKey])

  async function handleCopy(text, label) {
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setNotice(`${label} copied.`)
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
      if (data?.api_key) {
        setStoredApiKey(data.api_key)
      }
      await loadSettings()
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
          <h2 className="page-title">Settings</h2>
          <p className="subtle">Manage a stable API key and configure any GitHub repository for NetGuard scanning.</p>
        </div>
      </div>

      {loading && <div className="panel">Loading settings…</div>}
      {!loading && error && <div className="fix-error">{error}</div>}
      {!loading && notice && <div className="fix-success">{notice}</div>}

      {!loading && settings && (
        <>
          <section className="panel card-elevated fade-in" style={{ marginBottom: '1rem' }}>
            <h3 style={{ marginTop: 0 }}>Organization</h3>
            <div className="section-grid">
              <Info label="Organization" value={settings.org_name || '-'} />
              <Info label="User email" value={settings.user_email || '-'} />
            </div>
          </section>

          <section className="panel card-elevated fade-in" style={{ marginBottom: '1rem' }}>
            <h3 style={{ marginTop: 0 }}>Stable API key</h3>
            <p className="subtle" style={{ marginTop: 0 }}>
              This key does not rotate on login. Use it in GitHub Actions as <code>NETGUARD_API_KEY</code>.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '0.6rem', alignItems: 'center' }}>
              <input readOnly value={displayApiKey} style={{ fontFamily: 'SF Mono, Monaco, Consolas, monospace' }} />
              <button type="button" className="btn btn-ghost" onClick={() => setShowApiKey((v) => !v)}>
                {showApiKey ? 'Hide' : 'Show'}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => handleCopy(settings.api_key, 'API key')}>
                Copy
              </button>
            </div>
            <div style={{ display: 'flex', gap: '0.6rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
              <button type="button" className="btn" disabled={regenerating} onClick={handleRegenerate}>
                {regenerating ? 'Regenerating…' : 'Regenerate API key'}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => handleCopy(settings.hmac_secret, 'HMAC secret')}>
                Copy NETGUARD_SECRET
              </button>
            </div>
            <p className="subtle" style={{ marginBottom: 0 }}>
              If you regenerate this key, immediately update <code>NETGUARD_API_KEY</code> in every connected repository.
            </p>
          </section>

          <section className="panel card-elevated fade-in">
            <h3 style={{ marginTop: 0 }}>Connect a repository</h3>
            <p className="subtle" style={{ marginTop: 0 }}>
              Enter any GitHub repository as <code>owner/repo</code>. Then copy these values into that repository’s Actions secrets.
            </p>
            <label className="auth-label">GitHub repository name</label>
            <input
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder="owner/repo"
              autoComplete="off"
            />
            {repoName.trim() && (
              <div style={{ marginTop: '0.85rem' }}>
                <ol style={{ marginTop: 0, paddingLeft: '1.25rem', lineHeight: 1.8 }}>
                  <li>
                    In <strong>{repoName.trim()}</strong>, copy <code>{WORKFLOW_PATH}</code> from this project.
                  </li>
                  <li>
                    Add repository secrets:
                    <ul style={{ marginTop: '0.35rem' }}>
                      <li><code>NETGUARD_API_URL</code> = your NetGuard API base URL (from your deployment operator)</li>
                      <li><code>NETGUARD_SECRET</code> = <code>{settings.hmac_secret}</code></li>
                      <li><code>NETGUARD_API_KEY</code> = <code>{settings.api_key_masked}</code> (use Copy API key above for full value)</li>
                    </ul>
                  </li>
                  <li>Open or update a PR in that repository to trigger the NetGuard scan.</li>
                </ol>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}

function Info({ label, value }) {
  return (
    <div style={{ background: '#0d1527', border: '1px solid var(--border)', borderRadius: 10, padding: '0.55rem 0.65rem' }}>
      <div style={{ color: 'var(--text-subtle)', fontSize: '0.75rem', marginBottom: 2 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600, wordBreak: 'break-all' }}>{value}</div>
    </div>
  )
}
