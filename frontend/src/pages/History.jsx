import { useState, useEffect } from 'react'
import api from '../api/client'
import styles from './History.module.css'

const VERDICT_COLOR = {
  PHISHING:   'var(--red)',
  SUSPICIOUS: 'var(--amber)',
  SAFE:       'var(--green)',
  TRUSTED:    'var(--cyan)',
}

function formatDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('en-IN', {
    dateStyle: 'medium',
    timeStyle: 'short',
    hour12: true   // 12hr format
  })
}

export default function History() {
  const [data,     setData]     = useState(null)
  const [page,     setPage]     = useState(1)
  const [loading,  setLoading]  = useState(true)
  const [clearing, setClearing] = useState(false)

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

  return (
    <div>
      <div className={styles.topBar}>
        <div>
          <div className="sec-lbl" style={{ marginBottom: 2 }}>Scan History</div>
          <div className={styles.subtitle}>
            {data ? `${data.total} total scans saved in your account` : 'Loading...'}
          </div>
        </div>
        {data?.total > 0 && (
          <button className="pg-btn danger sm" onClick={clearAll} disabled={clearing}>
            {clearing ? 'Clearing...' : '🗑️ Clear All'}
          </button>
        )}
      </div>

      {loading ? (
        <div className="full-center" style={{ minHeight: 200 }}>
          <div className="spinner" />
        </div>
      ) : !data?.scans?.length ? (
        <div className="panel" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>🔍</div>
          <div style={{ fontFamily: 'var(--ff-body)', color: 'var(--txt3)', fontSize: 14 }}>
            No scans yet. Head to the Scanner to analyse some URLs.
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
                {data.scans.map(s => (
                  <tr key={s.id}>
                    <td className={styles.urlCell}>{s.url}</td>
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
                      <button className={styles.deleteBtn} onClick={() => deleteSingle(s.id)}
                        title="Delete this scan">✕</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {data.total_pages > 1 && (
            <div className={styles.pagination}>
              <button className="pg-btn ghost sm" disabled={page <= 1}
                onClick={() => fetchHistory(page - 1)}>← Prev</button>
              <span className={styles.pageInfo}>
                Page {page} of {data.total_pages}
              </span>
              <button className="pg-btn ghost sm" disabled={page >= data.total_pages}
                onClick={() => fetchHistory(page + 1)}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
