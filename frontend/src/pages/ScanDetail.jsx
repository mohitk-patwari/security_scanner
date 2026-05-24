import { useEffect, useMemo, useState, Fragment } from 'react'
import { createPortal } from 'react-dom'
import { useParams, Link } from 'react-router-dom'
import { fetchScan, fetchOverrides, postOverride, proposeFix, fetchScanFixes, postGithubFixComment } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import { 
  Target, 
  Shield, 
  Wrench, 
  CheckCircle, 
  AlertCircle, 
  XCircle,
  FileCode,
  ChevronDown,
  Copy,
  ExternalLink,
  Loader2
} from 'lucide-react'

export default function ScanDetail() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [tab, setTab] = useState('all')
  const [sortCol, setSortCol] = useState('severity')
  const [sortAsc, setSortAsc] = useState(false)
  const [overrides, setOverrides] = useState([])
  const [overrideForm, setOverrideForm] = useState({ finding_type: '', resource_pattern: '*', justification: '' })

  const [fixBusy, setFixBusy] = useState({})
  const [fixCache, setFixCache] = useState({})
  const [fixList, setFixList] = useState([])
  const [expandedDiffs, setExpandedDiffs] = useState({})
  const [ghPostBusyId, setGhPostBusyId] = useState(null)
  const [ghPostSuccess, setGhPostSuccess] = useState(null) // { commentUrl, prNumber, repository }
  const [ghPostError, setGhPostError] = useState(null) // { proposalId, message }
  const [ghPatModal, setGhPatModal] = useState(null) // { proposalId, token, busy, error }

  const hydrateFixes = (items) => {
    setFixList(items)
    if (!items.length) return
    setFixCache((cache) => {
      const next = { ...cache }
      for (const item of items) {
        if (!item.finding_id || next[item.finding_id]) continue
        next[item.finding_id] = {
          proposal_id: item.id,
          status: item.status,
          validation_errors: item.validation_errors,
          unified_diff_preview: item.unified_diff_preview,
          github_comment_id: item.github_comment_id,
        }
      }
      return next
    })
  }

  useEffect(() => {
    fetchScan(scanId).then(setScan).catch(() => setScan(null))
    fetchScanFixes(scanId).then((d) => hydrateFixes(d.items || [])).catch(() => hydrateFixes([]))
    fetchOverrides().then((d) => setOverrides(d.items || [])).catch(() => {})
  }, [scanId])

  const refreshFixes = () => {
    fetchScanFixes(scanId).then((d) => hydrateFixes(d.items || [])).catch(() => {})
  }

  const proposalForFinding = (findingId) => {
    const cached = fixCache[findingId]
    if (cached?.proposal_id) return cached
    const stored = fixList.find((x) => x.finding_id === findingId && x.id)
    return stored ? { ...cached, proposal_id: stored.id, github_comment_id: stored.github_comment_id, status: stored.status, unified_diff_preview: stored.unified_diff_preview ?? cached?.unified_diff_preview } : cached
  }

  const runSuggestFix = async (findingId) => {
    setFixBusy((b) => ({ ...b, [findingId]: true }))
    try {
      const r = await proposeFix(scanId, findingId)
      setFixCache((c) => ({ ...c, [findingId]: r }))
      refreshFixes()
    } catch (err) {
      setFixCache((c) => ({ ...c, [findingId]: { error: err.message || String(err) } }))
    } finally {
      setFixBusy((b) => ({ ...b, [findingId]: false }))
    }
  }

  const closeGhPatModal = () => {
    if (ghPatModal?.busy) return
    setGhPatModal(null)
  }

  const postToGithubPr = async (proposalId, githubToken = '') => {
    setGhPostError(null)
    setGhPostSuccess(null)
    setGhPostBusyId(proposalId)
    try {
      const res = await postGithubFixComment(proposalId, githubToken)
      if (!res?.posted) {
        throw new Error('Server did not confirm the GitHub comment was posted')
      }
      refreshFixes()
      setGhPatModal(null)
      setGhPostSuccess({
        commentUrl: res.comment_url || null,
        prNumber: res.pr_number ?? scan?.pr_number,
        repository: res.repository ?? scan?.repository,
        githubCommentId: res.github_comment_id || null,
      })
    } catch (err) {
      const msg = err.message || String(err)
      if (/no github token/i.test(msg)) {
        setGhPatModal({ proposalId, token: '', busy: false, error: msg })
      } else {
        setGhPostError({ proposalId, message: msg })
        setGhPatModal(null)
      }
    } finally {
      setGhPostBusyId(null)
    }
  }

  const submitGhPatPost = async () => {
    if (!ghPatModal?.proposalId) return
    const token = (ghPatModal.token || '').trim()
    if (!token) {
      setGhPatModal((m) => ({ ...m, error: 'Paste a GitHub PAT with repo scope, or set GITHUB_TOKEN on the API server.' }))
      return
    }
    setGhPatModal((m) => ({ ...m, busy: true, error: '' }))
    await postToGithubPr(ghPatModal.proposalId, token)
  }

  const closeGhPostSuccess = () => setGhPostSuccess(null)

  const ghModals = (ghPatModal || ghPostSuccess) && createPortal(
    <>
      {ghPatModal && (
        <div className="modal-backdrop" onClick={closeGhPatModal} role="presentation">
          <div
            className="modal-card-solid"
            role="dialog"
            aria-modal="true"
            aria-labelledby="gh-pat-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id="gh-pat-title" className="modal-title">GitHub token required</h3>
            <p className="modal-body-text">
              The API server has no <code>GITHUB_TOKEN</code>. Paste a PAT with <code>repo</code> scope to post the autofix comment.
            </p>
            <label className="auth-label" htmlFor="gh-pat-input">GitHub PAT</label>
            <input
              id="gh-pat-input"
              type="password"
              autoComplete="off"
              placeholder="github_pat_…"
              value={ghPatModal.token}
              disabled={ghPatModal.busy}
              onChange={(e) => setGhPatModal((m) => ({ ...m, token: e.target.value, error: '' }))}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !ghPatModal.busy) submitGhPatPost()
                if (e.key === 'Escape' && !ghPatModal.busy) closeGhPatModal()
              }}
            />
            {ghPatModal.error && (
              <div className="fix-error" style={{ marginTop: '0.75rem' }}>
                {ghPatModal.error}
              </div>
            )}
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" disabled={ghPatModal.busy} onClick={closeGhPatModal}>
                Cancel
              </button>
              <button type="button" className="btn" disabled={ghPatModal.busy} onClick={submitGhPatPost}>
                {ghPatModal.busy ? 'Posting…' : 'Post comment'}
              </button>
            </div>
          </div>
        </div>
      )}

      {ghPostSuccess && (
        <div className="modal-backdrop modal-backdrop-success" onClick={closeGhPostSuccess} role="presentation">
          <div
            className="modal-card-solid modal-card-success"
            role="dialog"
            aria-modal="true"
            aria-labelledby="gh-post-success-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-success-icon" aria-hidden="true">
              <CheckCircle size={40} strokeWidth={2.5} />
            </div>
            <h2 id="gh-post-success-title" className="modal-success-headline">
              Comment posted to PR successfully
            </h2>
            <p className="modal-body-text modal-success-message">
              Fix posted on the pull request for the misconfigured infrastructure.
            </p>
            {(ghPostSuccess.repository || ghPostSuccess.prNumber != null) && (
              <p className="modal-success-meta">
                {ghPostSuccess.repository || 'Repository'}
                {ghPostSuccess.prNumber != null ? ` · PR #${ghPostSuccess.prNumber}` : ''}
              </p>
            )}
            {ghPostSuccess.commentUrl && (
              <a
                href={ghPostSuccess.commentUrl}
                target="_blank"
                rel="noreferrer"
                className="btn btn-ghost modal-success-link"
              >
                <ExternalLink size={16} />
                View comment on GitHub
              </a>
            )}
            <div className="modal-actions modal-actions-center">
              <button type="button" className="btn modal-ok-btn" onClick={closeGhPostSuccess} autoFocus>
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </>,
    document.body,
  )

  const toggleDiff = (findingId) => {
    setExpandedDiffs((prev) => ({ ...prev, [findingId]: !prev[findingId] }))
  }

  const copyDiff = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  const findings = useMemo(() => scan?.findings || [], [scan])

  const filtered = useMemo(() => {
    let list = findings
    if (tab === 'new') list = list.filter((f) => f.is_new)
    else if (tab === 'unchanged') list = list.filter((f) => !f.is_new)
    const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
    list = [...list].sort((a, b) => {
      if (sortCol === 'severity') return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0)
      if (sortCol === 'type') return (a.finding_type || '').localeCompare(b.finding_type || '')
      if (sortCol === 'blast') return (b.blast_radius_count || 0) - (a.blast_radius_count || 0)
      return 0
    })
    if (sortAsc) list.reverse()
    return list
  }, [findings, tab, sortCol, sortAsc])

  const toggleSort = (col) => {
    if (sortCol === col) setSortAsc(!sortAsc)
    else { setSortCol(col); setSortAsc(false) }
  }

  const submitOverride = async () => {
    if (!overrideForm.finding_type) return
    try {
      await postOverride(overrideForm)
      const refreshed = await fetchOverrides()
      setOverrides(refreshed.items || [])
      setOverrideForm({ finding_type: '', resource_pattern: '*', justification: '' })
    } catch { /* ignore */ }
  }

  if (!scan) return <p style={{ color: '#94a3b8' }}>Loading scan #{scanId}...</p>

  return (
    <>
    {ghModals}
    <div className="page">
      <div className="panel card-elevated">
        <div className="page-header">
          <div>
            <h2 className="page-title">Scan #{scan.id}</h2>
            <p className="subtle">Status: {scan.status} · PR {scan.pr_number ?? '-'} · Commit {scan.commit_sha ?? '-'} · {scan.created_at}</p>
          </div>
          <Link to={`/scans/${scanId}/graph`} className="btn btn-ghost" style={{ textDecoration: 'none' }}>
            View topology graph
          </Link>
        </div>
        {fixList.length > 0 && (
          <p className="subtle" style={{ marginTop: 8 }}>
            Autofix proposals stored: {fixList.length}
          </p>
        )}
      </div>

      <div className="panel fade-in">
        <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
          {['all', 'new', 'unchanged'].map((t) => (
            <button key={t} onClick={() => setTab(t)} className={`btn ${tab === t ? '' : 'btn-ghost'}`}>
              {t[0].toUpperCase() + t.slice(1)} ({t === 'all' ? findings.length : t === 'new' ? findings.filter((f) => f.is_new).length : findings.filter((f) => !f.is_new).length})
            </button>
          ))}
        </div>

        <div className="table-wrap">
          <table>
          <thead>
            <tr>
              <Th label="Finding type" col="type" sortCol={sortCol} sortAsc={sortAsc} onClick={toggleSort} />
              <Th label="Severity" col="severity" sortCol={sortCol} sortAsc={sortAsc} onClick={toggleSort} />
              <th>Location</th>
              <Th label="Blast radius" col="blast" sortCol={sortCol} sortAsc={sortAsc} onClick={toggleSort} />
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => {
              const proposal = proposalForFinding(f.id)
              const proposalId = proposal?.proposal_id
              const alreadyPosted = Boolean(proposal?.github_comment_id)
              return (
              <Fragment key={f.id}>
              <tr>
                <td>{f.finding_type}</td>
                <td><SeverityBadge severity={f.severity} /></td>
                <td>
                  {f.source_file != null && f.source_line != null ? (
                    f.github_url ? (
                      <a href={f.github_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: '0.85rem' }}>
                        {f.source_file}:{f.source_line}
                      </a>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{f.source_file}:{f.source_line}</span>
                    )
                  ) : (
                    <span style={{ color: 'var(--text-subtle)', fontSize: '0.8rem' }}>-</span>
                  )}
                </td>
                <td>{f.blast_radius_count ?? 0}</td>
                <td>
                  {f.is_new ? <span className="chip chip-success">New</span> : <span className="chip">Unchanged</span>}
                  {f.overridden ? <span className="chip chip-warning" style={{ marginLeft: 6 }}>Overridden</span> : null}
                </td>
                <td>
                  <div className="action-buttons">
                    <Link
                      to={`/scans/${scanId}/graph`}
                      state={{
                        highlight: [
                          f.resource_id,
                          ...(Array.isArray(f.blast_radius_resources) ? f.blast_radius_resources : []),
                        ].filter(Boolean),
                        focusNode: f.resource_id || null,
                      }}
                      className="btn btn-ghost"
                    >
                      <Target />
                      Highlight blast
                    </Link>
                    <button 
                      type="button" 
                      onClick={() => setOverrideForm((p) => ({ ...p, finding_type: f.finding_type }))} 
                      className="btn btn-ghost"
                    >
                      <Shield />
                      Override
                    </button>
                    <button 
                      type="button" 
                      disabled={!!fixBusy[f.id]} 
                      onClick={() => runSuggestFix(f.id)} 
                      className="btn btn-warning"
                    >
                      {fixBusy[f.id] ? <Loader2 className="spinner" /> : <Wrench />}
                      {fixBusy[f.id] ? 'Processing...' : 'Suggest fix'}
                    </button>
                  </div>
                </td>
              </tr>
              {fixCache[f.id] && (
                <tr>
                  <td colSpan={6} style={{ padding: '0.75rem', verticalAlign: 'top' }}>
                    <div className="fix-preview-card">
                      {fixCache[f.id].error ? (
                        <div className="fix-error">
                          <XCircle />
                          <span>{fixCache[f.id].error}</span>
                        </div>
                      ) : (
                        <>
                          <div className="fix-preview-header">
                            <div className="fix-preview-status">
                              <div className={`status-badge ${fixCache[f.id].status === 'validated' ? 'validated' : fixCache[f.id].status === 'pending' ? 'pending' : 'error'}`}>
                                {fixCache[f.id].status === 'validated' ? (
                                  <>
                                    <CheckCircle />
                                    <span>Validated</span>
                                  </>
                                ) : fixCache[f.id].status === 'pending' ? (
                                  <>
                                    <AlertCircle />
                                    <span>Pending</span>
                                  </>
                                ) : (
                                  <>
                                    <XCircle />
                                    <span>Error</span>
                                  </>
                                )}
                              </div>
                              {fixCache[f.id].regression_detail && (
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                                  {fixCache[f.id].regression_detail}
                                </span>
                              )}
                            </div>
                          </div>

                          {fixCache[f.id].validation_errors?.length > 0 && (
                            <div className="validation-errors">
                              <AlertCircle />
                              <span>{fixCache[f.id].validation_errors.join('; ')}</span>
                            </div>
                          )}

                          {fixCache[f.id].unified_diff_preview && (
                            <div className="diff-section">
                              <div 
                                className="diff-header" 
                                onClick={() => toggleDiff(f.id)}
                              >
                                <div className="diff-header-label">
                                  <FileCode />
                                  <span>Diff Preview</span>
                                  <span style={{ color: 'var(--text-subtle)', fontSize: '0.75rem' }}>
                                    ({fixCache[f.id].unified_diff_preview.split('\n').length} lines)
                                  </span>
                                </div>
                                <div className={`diff-toggle ${expandedDiffs[f.id] === false ? 'collapsed' : ''}`}>
                                  <ChevronDown />
                                </div>
                              </div>
                              {expandedDiffs[f.id] !== false && (
                                <pre className="diff-container">
                                  {fixCache[f.id].unified_diff_preview.split('\n').map((line, idx) => {
                                    if (line.startsWith('+') && !line.startsWith('+++')) {
                                      return <span key={idx} className="diff-line-add">{line}{'\n'}</span>
                                    } else if (line.startsWith('-') && !line.startsWith('---')) {
                                      return <span key={idx} className="diff-line-remove">{line}{'\n'}</span>
                                    } else {
                                      return <span key={idx} className="diff-line-context">{line}{'\n'}</span>
                                    }
                                  })}
                                </pre>
                              )}
                            </div>
                          )}

                          <div className="button-group">
                            {fixCache[f.id].unified_diff_preview && (
                              <button 
                                type="button" 
                                onClick={() => copyDiff(fixCache[f.id].unified_diff_preview)} 
                                className="btn btn-ghost"
                              >
                                <Copy />
                                Copy diff
                              </button>
                            )}
                            {ghPostError?.proposalId === proposalId && (
                              <div className="fix-error" style={{ width: '100%' }}>
                                <AlertCircle />
                                {ghPostError.message}
                              </div>
                            )}
                            {proposalId && scan?.pr_number != null && (
                              alreadyPosted ? (
                                <span className="subtle" style={{ fontSize: '0.85rem' }}>
                                  <CheckCircle style={{ width: 14, height: 14, verticalAlign: 'middle', marginRight: 4, color: 'var(--success)' }} />
                                  Posted to PR #{scan.pr_number}
                                </span>
                              ) : (
                              <button 
                                type="button" 
                                onClick={() => postToGithubPr(proposalId)} 
                                className="btn"
                                disabled={ghPostBusyId === proposalId}
                              >
                                {ghPostBusyId === proposalId ? (
                                  <Loader2 className="spinner" />
                                ) : (
                                  <ExternalLink />
                                )}
                                {ghPostBusyId === proposalId ? 'Posting…' : 'Post to GitHub PR'}
                              </button>
                              )
                            )}
                            {proposalId && scan?.pr_number == null && (
                              <span className="subtle" style={{ fontSize: '0.85rem' }}>
                                PR number missing — run scan from GitHub Actions on a pull request.
                              </span>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              )}
              </Fragment>
            )})}
            {filtered.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: '#64748b' }}>No findings.</td></tr>}
          </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <h3 style={{ margin: '0 0 0.75rem' }}>Overrides</h3>
        <div className="section-grid">
          <div>
            <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem', color: 'var(--text-muted)' }}>New override request</h4>
            <input placeholder="Finding type" value={overrideForm.finding_type} onChange={(e) => setOverrideForm((p) => ({ ...p, finding_type: e.target.value }))} />
            <input placeholder="Resource pattern" value={overrideForm.resource_pattern} onChange={(e) => setOverrideForm((p) => ({ ...p, resource_pattern: e.target.value }))} />
            <textarea placeholder="Justification" value={overrideForm.justification} onChange={(e) => setOverrideForm((p) => ({ ...p, justification: e.target.value }))} rows={2} />
            <button onClick={submitOverride} type="button" className="btn">Submit override</button>
          </div>
          <div>
            <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem', color: 'var(--text-muted)' }}>Active overrides</h4>
            {overrides.length === 0 ? (
              <p className="subtle">No active overrides.</p>
            ) : (
              <ul style={{ margin: 0, paddingLeft: 16, fontSize: '0.9rem' }}>{overrides.map((o) => <li key={o.id}>{o.finding_type} :: {o.resource_pattern}</li>)}</ul>
            )}
          </div>
        </div>
      </div>

    </div>
    </>
  )
}

function Th({ label, col, sortCol, sortAsc, onClick }) {
  const active = sortCol === col
  return (
    <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => onClick(col)}>
      {label} {active ? (sortAsc ? '▲' : '▼') : ''}
    </th>
  )
}
