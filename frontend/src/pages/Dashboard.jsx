import { useState } from 'react'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import ScanResult from '../components/ScanResult'
import styles from './Dashboard.module.css'

export default function Dashboard() {
  const { user } = useAuth()
  const [tab, setTab]         = useState('single')
  const [url, setUrl]         = useState('')
  const [batchText, setBatch] = useState('')
  const [result, setResult]   = useState(null)
  const [batchResult, setBatchResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')

  const scanSingle = async () => {
    if (!url.trim()) { setError('Please enter a URL.'); return }
    setError(''); setLoading(true); setResult(null)
    try {
      const { data } = await api.post('/scan/single', { url: url.trim() })
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Scan failed.')
    } finally { setLoading(false) }
  }

  const scanBatch = async () => {
    const urls = batchText.split('\n').map(u => u.trim()).filter(Boolean)
    if (!urls.length) { setError('Please enter at least one URL.'); return }
    setError(''); setLoading(true); setBatchResult(null)
    try {
      const { data } = await api.post('/scan/batch', { urls })
      setBatchResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Batch scan failed.')
    } finally { setLoading(false) }
  }

  const verdictColor = { PHISHING: 'var(--red)', SUSPICIOUS: 'var(--amber)', SAFE: 'var(--green)', TRUSTED: 'var(--cyan)' }

  return (
    <div>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.hdrLeft}>
          <div className={styles.hdrIcon}>🛡️</div>
          <div>
            <div className={styles.hdrTitle}>PHISHGUARD AI</div>
            <div className={styles.hdrSub}>PHISHING URL THREAT DETECTION SYSTEM v2.0</div>
          </div>
        </div>
        <div className={styles.statRow}>
          <div className={styles.statCard}>
            <span className={styles.statVal}>{user?.total_scans ?? 0}</span>
            <span className={styles.statLbl}>Total Scans</span>
          </div>
          <div className={styles.statCard}>
            <span className={styles.statVal} style={{ color: 'var(--red)' }}>{user?.phishing_found ?? 0}</span>
            <span className={styles.statLbl}>Threats Found</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className={styles.tabs}>
        {['single', 'batch'].map(t => (
          <button key={t} className={`${styles.tabBtn} ${tab === t ? styles.tabActive : ''}`}
            onClick={() => { setTab(t); setResult(null); setBatchResult(null); setError('') }}>
            {t === 'single' ? '🔍 Single URL' : '📋 Batch Scan'}
          </button>
        ))}
      </div>

      {/* Single scan */}
      {tab === 'single' && (
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="sec-lbl">Scan a URL</div>
          <div className={styles.inputRow}>
            <input className="pg-input" value={url} onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              onKeyDown={e => e.key === 'Enter' && scanSingle()} />
            <button className="pg-btn sm" onClick={scanSingle} disabled={loading} style={{ flexShrink: 0 }}>
              {loading ? 'Scanning...' : 'Scan'}
            </button>
          </div>
          {error && <div className="error-msg" style={{ marginTop: 10 }}>{error}</div>}
        </div>
      )}

      {/* Batch scan */}
      {tab === 'batch' && (
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="sec-lbl">Batch Scan (one URL per line, max 50)</div>
          <textarea className={`pg-input ${styles.textarea}`}
            value={batchText} onChange={e => setBatch(e.target.value)}
            placeholder={"http://example.com\nhttp://suspicious-site.ru\nhttp://paypal.verify-now.xyz"} />
          <div style={{ marginTop: 12 }}>
            <button className="pg-btn sm" onClick={scanBatch} disabled={loading}>
              {loading ? 'Scanning...' : `Scan ${batchText.split('\n').filter(l => l.trim()).length} URLs`}
            </button>
          </div>
          {error && <div className="error-msg" style={{ marginTop: 10 }}>{error}</div>}
        </div>
      )}

      {/* Single result */}
      {result && <ScanResult result={result} />}

      {/* Batch results */}
      {batchResult && (
        <div>
          {/* Summary */}
          <div className={styles.batchSummary}>
            {[
              { label: 'Scanned', val: batchResult.summary.total, color: 'var(--cyan)' },
              { label: 'Phishing', val: batchResult.summary.phishing, color: 'var(--red)' },
              { label: 'Suspicious', val: batchResult.summary.suspicious, color: 'var(--amber)' },
              { label: 'Safe', val: batchResult.summary.safe, color: 'var(--green)' },
            ].map(s => (
              <div key={s.label} className={styles.summaryCard}>
                <span className={styles.summaryVal} style={{ color: s.color }}>{s.val}</span>
                <span className={styles.summaryLbl}>{s.label}</span>
              </div>
            ))}
          </div>

          {/* Table */}
          <div className="panel" style={{ overflowX: 'auto' }}>
            <table className={styles.batchTable}>
              <thead>
                <tr>
                  {['URL','Final Score','ML Score','URL Risk','Verdict','Flags'].map(h => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {batchResult.results.map((r, i) => (
                  <tr key={i}>
                    <td className={styles.urlCell}>{r.url}</td>
                    <td style={{ color: verdictColor[r.verdict] ?? 'var(--txt2)', fontWeight: 700 }}>
                      {(r.final_proba * 100).toFixed(1)}%
                    </td>
                    <td>{(r.model_proba * 100).toFixed(1)}%</td>
                    <td>{(r.url_risk * 100).toFixed(1)}%</td>
                    <td style={{ color: verdictColor[r.verdict] ?? 'var(--txt2)', fontWeight: 700 }}>
                      {r.verdict}
                    </td>
                    <td>{r.flags?.length ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
