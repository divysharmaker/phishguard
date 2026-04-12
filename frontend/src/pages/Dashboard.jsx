import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import ScanResult from '../components/ScanResult'
import styles from './Dashboard.module.css'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'

// ── Live Clock ──
function LiveClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return (
    <div className={styles.clock}>
      <div className={styles.clockTime}>
        {time.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true })}
      </div>
      <div className={styles.clockDate}>
        {time.toLocaleDateString('en-IN', { weekday: 'short', day: 'numeric', month: 'short' })}
      </div>
    </div>
  )
}

// ── Weather Widget ──
function WeatherWidget() {
  const [weather, setWeather] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    navigator.geolocation?.getCurrentPosition(
      async ({ coords }) => {
        try {
          const res = await fetch(
            `https://api.open-meteo.com/v1/forecast?latitude=${coords.latitude}&longitude=${coords.longitude}&current_weather=true&hourly=relativehumidity_2m`
          )
          const data = await res.json()
          const cw = data.current_weather
          const weatherCodes = {
            0: '☀️ Clear', 1: '🌤️ Mostly clear', 2: '⛅ Partly cloudy',
            3: '☁️ Overcast', 45: '🌫️ Foggy', 48: '🌫️ Foggy',
            51: '🌦️ Drizzle', 61: '🌧️ Rain', 71: '❄️ Snow',
            80: '🌧️ Showers', 95: '⛈️ Thunderstorm'
          }
          setWeather({
            temp: Math.round(cw.temperature),
            desc: weatherCodes[cw.weathercode] || '🌡️ Unknown',
            wind: Math.round(cw.windspeed),
          })
        } catch { setWeather(null) }
        setLoading(false)
      },
      () => setLoading(false)
    )
  }, [])

  if (loading) return <div className={styles.weather}>🌡️ Loading...</div>
  if (!weather) return <div className={styles.weather}>📍 Enable location</div>
  return (
    <div className={styles.weather}>
      <div className={styles.weatherTemp}>{weather.temp}°C</div>
      <div className={styles.weatherDesc}>{weather.desc}</div>
      <div className={styles.weatherWind}>💨 {weather.wind} km/h</div>
    </div>
  )
}

// ── Charts ──
function StatsCharts({ totalScans, phishingFound }) {
  const safe = Math.max(0, totalScans - phishingFound)
  const pieData = [
    { name: 'Phishing', value: phishingFound },
    { name: 'Safe', value: safe },
  ]
  const barData = [
    { name: 'Total', value: totalScans },
    { name: 'Threats', value: phishingFound },
    { name: 'Safe', value: safe },
  ]
  const COLORS = ['#ff2d55', '#00e676']

  if (totalScans === 0) return null

  return (
    <div className={styles.chartsRow}>
      <div className={styles.chartCard}>
        <div className={styles.chartTitle}>Scan Breakdown</div>
        <ResponsiveContainer width="100%" height={140}>
          <PieChart>
            <Pie data={pieData} cx="50%" cy="50%" innerRadius={35} outerRadius={55} dataKey="value">
              {pieData.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
            </Pie>
            <Tooltip formatter={(v, n) => [`${v}`, n]} contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '11px' }} />
          </PieChart>
        </ResponsiveContainer>
        <div className={styles.chartLegend}>
          <span style={{ color: '#ff2d55' }}>● Phishing: {phishingFound}</span>
          <span style={{ color: '#00e676' }}>● Safe: {safe}</span>
        </div>
      </div>

      <div className={styles.chartCard}>
        <div className={styles.chartTitle}>Scan Summary</div>
        <ResponsiveContainer width="100%" height={140}>
          <BarChart data={barData} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--txt2)' }} />
            <YAxis tick={{ fontSize: 10, fill: 'var(--txt2)' }} />
            <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '11px' }} />
            <Bar dataKey="value" fill="var(--cyan)" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

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
            <div className={styles.hdrTitle}>PhishGuard</div>
            <div className={styles.hdrSub}>URL Threat Detection System</div>
          </div>
        </div>
        <div className={styles.hdrRight}>
          <WeatherWidget />
          <div className={styles.statRow}>
            <div className={styles.statCard}>
              <span className={styles.statVal}>{user?.total_scans ?? 0}</span>
              <span className={styles.statLbl}>Scans</span>
            </div>
            <div className={styles.statCard}>
              <span className={styles.statVal} style={{ color: 'var(--red)' }}>{user?.phishing_found ?? 0}</span>
              <span className={styles.statLbl}>Threats</span>
            </div>
          </div>
          <LiveClock />
        </div>
      </div>

      {/* Welcome */}
      <p style={{ fontSize: '13px', color: 'var(--txt2)', marginBottom: '14px', padding: '0 2px' }}>
        Welcome back, <strong style={{ color: 'var(--txt1)' }}>{user?.name}</strong>! Paste a URL to check if it's safe.
      </p>

      {/* Charts */}
      <StatsCharts totalScans={user?.total_scans ?? 0} phishingFound={user?.phishing_found ?? 0} />

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
              {loading ? '...' : 'Scan'}
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
            placeholder={"http://example.com\nhttp://suspicious-site.ru"} />
          <div style={{ marginTop: 12 }}>
            <button className="pg-btn sm" onClick={scanBatch} disabled={loading}>
              {loading ? 'Scanning...' : `Scan ${batchText.split('\n').filter(l => l.trim()).length} URLs`}
            </button>
          </div>
          {error && <div className="error-msg" style={{ marginTop: 10 }}>{error}</div>}
        </div>
      )}

      {result && <ScanResult result={result} />}

      {batchResult && (
        <div>
          <div className={styles.batchSummary}>
            {[
              { label: 'Scanned',    val: batchResult.summary.total,      color: 'var(--cyan)'  },
              { label: 'Phishing',   val: batchResult.summary.phishing,   color: 'var(--red)'   },
              { label: 'Suspicious', val: batchResult.summary.suspicious, color: 'var(--amber)' },
              { label: 'Safe',       val: batchResult.summary.safe,       color: 'var(--green)' },
            ].map(s => (
              <div key={s.label} className={styles.summaryCard}>
                <span className={styles.summaryVal} style={{ color: s.color }}>{s.val}</span>
                <span className={styles.summaryLbl}>{s.label}</span>
              </div>
            ))}
          </div>
          <div className="panel" style={{ overflowX: 'auto' }}>
            <table className={styles.batchTable}>
              <thead>
                <tr>{['URL','Score','ML','Risk','Verdict','Flags'].map(h => <th key={h}>{h}</th>)}</tr>
              </thead>
              <tbody>
                {batchResult.results.map((r, i) => (
                  <tr key={i}>
                    <td className={styles.urlCell}>{r.url}</td>
                    <td style={{ color: verdictColor[r.verdict] ?? 'var(--txt2)', fontWeight: 700 }}>{(r.final_proba * 100).toFixed(1)}%</td>
                    <td>{(r.model_proba * 100).toFixed(1)}%</td>
                    <td>{(r.url_risk * 100).toFixed(1)}%</td>
                    <td style={{ color: verdictColor[r.verdict] ?? 'var(--txt2)', fontWeight: 700 }}>{r.verdict}</td>
                    <td>{r.flags?.length ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div style={{ marginTop: '24px', padding: '10px 2px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '4px' }}>
        <span style={{ fontSize: '10px', color: 'var(--txt3)', fontFamily: 'var(--ff-mono)' }}>Final Year Project — Divyansh Sharma</span>
        <span style={{ fontSize: '10px', color: 'var(--txt3)', fontFamily: 'var(--ff-mono)' }}>Phishing URL Detection using ML · 2026</span>
      </div>
    </div>
  )
}
