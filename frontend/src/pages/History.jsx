import { useState, useEffect } from 'react'
import api from '../api/client'
import styles from './History.module.css'

const VERDICT_COLOR = {
  PHISHING:   'var(--red)',
  SUSPICIOUS: 'var(--amber)',
  SAFE:       'var(--green)',
  TRUSTED:    'var(--cyan)',
}
const VERDICT_ICON = { PHISHING: '🚨', SUSPICIOUS: '⚠️', SAFE: '✅', TRUSTED: '🔵' }

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', hour12: true })
}

export default function History() {
  const [data,     setData]     = useState(null)
  const [page,     setPage]     = useState(1)
  const [loading,  setLoading]  = useState(true)
  const [clearing, setClearing] = useState(false)
  const [search,   setSearch]   = useState('')
  const [filter,   setFilter]   = useState('ALL')   // ALL | PHISHING | SUSPICIOUS | SAFE | TRUSTED

  const fetchHistory = async (p = 1) => {
    setLoading(true)
    try {
      const { data: d } = await api.get(`/history/?page=${p}&limit=20`)
      setData(d); setPage(p)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchHistory(1) }, [])

  const clearAll = async () => {
    if (!window.confirm('Delete all scan history? This cannot be undone.')) return
    setClearing(true)
    try { await api.delete('/history/'); fetchHistory(1) }
    catch (e) { console.error(e) }
    finally { setClearing(false) }
  }

  const deleteSingle = async (id) => {
    try { await api.delete(`/history/${id}`); fetchHistory(page) }
    catch (e) { console.error(e) }
  }

  // Export CSV
  const exportCSV = () => {
    if (!data?.scans?.length) return
    const rows = [['URL', 'Verdict', 'Score', 'Type', 'Scanned At']]
    data.scans.forEach(s => {
      rows.push([
        `"${s.url}"`,
        s.verdict,
        s.final_proba != null ? `${(s.final_proba * 100).toFixed(1)}%` : '—',
        s.scan_type,
        formatDate(s.scanned_at),
      ])
    })
    const csv = rows.map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `phishguard-history-${new Date().toISOString().slice(0,10)}.csv`
    a.click()
  }

  // Client-side filter + search
  const filtered = data?.scans?.filter(s => {
    const matchFilter  = filter === 'ALL' || s.verdict === filter
    const matchSearch  = !search.trim() || s.url.toLowerCase().includes(search.toLowerCase())
    return matchFilter && matchSearch
  }) ?? []

  const verdictCounts = data?.scans?.reduce((acc, s) => {
    acc[s.verdict] = (acc[s.verdict] || 0) + 1; return acc
  }, {}) ?? {}

  return (
    <div>
      {/* Top bar */}
      <div className={styles.topBar}>
        <div>
          <div className="sec-lbl" style={{ marginBottom: 2 }}>Scan History</div>
          <div className={styles.subtitle}>
            {data ? `${data.total} total scans in your account` : 'Loading...'}
          </div>
        </div>
        <div className={styles.topActions}>
          {data?.total > 0 && (
            <button className="pg-btn ghost sm" onClick={exportCSV} title="Export as CSV">
              ⬇️ Export CSV
            </button>
          )}
          {data?.total > 0 && (
            <button className="pg-btn danger sm" onClick={clearAll} disabled={clearing}>
              {clearing ? 'Clearing...' : '🗑️ Clear All'}
            </button>
          )}
        </div>
      </div>

      {/* Stats row */}
      {data?.total > 0 && (
        <div className={styles.statsRow}>
          {['PHISHING','SUSPICIOUS','SAFE','TRUSTED'].map(v => (
            <div key={v} className={styles.statChip}
              style={{ borderColor: filter === v ? VERDICT_COLOR[v] : undefined,
                       background: filter === v ? `${VERDICT_COLOR[v]}15` : undefined }}
              onClick={() => setFilter(filter === v ? 'ALL' : v)}>
              <span className={styles.statIcon}>{VERDICT_ICON[v]}</span>
              <span className={styles.statCount} style={{ color: VERDICT_COLOR[v] }}>{verdictCounts[v] ?? 0}</span>
              <span className={styles.statName}>{v}</span>
            </div>
          ))}
        </div>
      )}

      {/* Search + filter row */}
      <div className={styles.searchRow}>
        <input className={`pg-input ${styles.searchInput}`}
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="🔍 Search by URL..." />
        <div className={styles.filterBtns}>
          {['ALL','PHISHING','SUSPICIOUS','SAFE'].map(v => (
            <button key={v}
              className={`${styles.filterBtn} ${filter === v ? styles.filterActive : ''}`}
              style={filter === v && v !== 'ALL' ? { color: VERDICT_COLOR[v], borderColor: VERDICT_COLOR[v] } : {}}
              onClick={() => setFilter(v)}>
              {v}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="full-center" style={{ minHeight: 200 }}>
          <div className="spinner" />
        </div>
      ) : !filtered.length ? (
        <div className="panel" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>
            {search || filter !== 'ALL' ? '🔍' : '📭'}
          </div>
          <div style={{ fontFamily: 'var(--ff-body)', color: 'var(--txt3)', fontSize: 14 }}>
            {search || filter !== 'ALL'
              ? 'No results match your search or filter.'
              : 'No scans yet. Head to the Scanner to analyse some URLs.'}
          </div>
        </div>
      ) : (
        <>
          <div className="panel" style={{ overflowX: 'auto', padding: 0 }}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Verdict</th>
                  <th>Score</th>
                  <th>Type</th>
                  <th>Scanned At</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(s => (
                  <tr key={s.id}>
                    <td className={styles.urlCell}>
                      <span className={styles.urlIcon}>{VERDICT_ICON[s.verdict] ?? '?'}</span>
                      {s.url.replace(/^https?:\/\//, '').slice(0, 50)}{s.url.length > 55 ? '…' : ''}
                    </td>
                    <td>
                      <span className={styles.verdictBadge}
                        style={{ color: VERDICT_COLOR[s.verdict] ?? 'var(--txt2)',
                                 borderColor: VERDICT_COLOR[s.verdict] ?? 'var(--border)' }}>
                        {s.verdict}
                      </span>
                    </td>
                    <td style={{ color: VERDICT_COLOR[s.verdict] ?? 'var(--txt2)', fontWeight: 700 }}>
                      {s.final_proba != null ? `${(s.final_proba * 100).toFixed(1)}%` : '—'}
                    </td>
                    <td>
                      <span className={styles.typeBadge}>{s.scan_type}</span>
                    </td>
                    <td className={styles.dateCell}>{formatDate(s.scanned_at)}</td>
                    <td>
                      <button className={styles.deleteBtn} onClick={() => deleteSingle(s.id)} title="Delete">✕</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {data.total_pages > 1 && (
            <div className={styles.pagination}>
              <button className="pg-btn ghost sm" disabled={page <= 1} onClick={() => fetchHistory(page - 1)}>← Prev</button>
              <span className={styles.pageInfo}>Page {page} of {data.total_pages}</span>
              <button className="pg-btn ghost sm" disabled={page >= data.total_pages} onClick={() => fetchHistory(page + 1)}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}