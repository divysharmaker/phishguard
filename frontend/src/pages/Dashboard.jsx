import { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import ScanResult from '../components/ScanResult'
import styles from './Dashboard.module.css'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line, Legend
} from 'recharts'

// ── Count-up hook ─────────────────────────────────────────────
function useCountUp(target, duration = 1000) {
  const [count, setCount] = useState(0)
  const prev = useRef(0)
  useEffect(() => {
    if (target === prev.current) return
    const start = prev.current
    const diff  = target - start
    const startTime = performance.now()
    const tick = (now) => {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3) // ease-out cubic
      setCount(Math.round(start + diff * eased))
      if (progress < 1) requestAnimationFrame(tick)
      else prev.current = target
    }
    requestAnimationFrame(tick)
  }, [target, duration])
  return count
}

// ── Fade-in on mount hook ─────────────────────────────────────
function useFadeIn(delay = 0) {
  const ref = useRef(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    el.style.opacity = '0'
    el.style.transform = 'translateY(14px)'
    el.style.transition = `opacity 0.5s ease ${delay}ms, transform 0.5s ease ${delay}ms`
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.style.opacity = '1'
        el.style.transform = 'translateY(0)'
      })
    })
  }, [delay])
  return ref
}

// ── Live Clock ────────────────────────────────────────────────
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

// ── Weather Widget ────────────────────────────────────────────
function WeatherWidget() {
  const [weather, setWeather] = useState(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    navigator.geolocation?.getCurrentPosition(
      async ({ coords }) => {
        try {
          const res = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${coords.latitude}&longitude=${coords.longitude}&current_weather=true`)
          const data = await res.json()
          const cw = data.current_weather
          const weatherCodes = { 0:'☀️ Clear',1:'🌤️ Mostly clear',2:'⛅ Partly cloudy',3:'☁️ Overcast',45:'🌫️ Foggy',48:'🌫️ Foggy',51:'🌦️ Drizzle',61:'🌧️ Rain',71:'❄️ Snow',80:'🌧️ Showers',95:'⛈️ Storm' }
          setWeather({ temp: Math.round(cw.temperature), desc: weatherCodes[cw.weathercode] || '🌡️', wind: Math.round(cw.windspeed) })
        } catch { setWeather(null) }
        setLoading(false)
      },
      () => setLoading(false)
    )
  }, [])
  if (loading) return <div className={styles.weather}><div className={styles.weatherTemp}>--°C</div></div>
  if (!weather) return null
  return (
    <div className={styles.weather}>
      <div className={styles.weatherTemp}>{weather.temp}°C</div>
      <div className={styles.weatherDesc}>{weather.desc}</div>
      <div className={styles.weatherWind}>💨 {weather.wind} km/h</div>
    </div>
  )
}

// ── Animated Stat Card ────────────────────────────────────────
function AnimatedStat({ value, label, color, delay = 0 }) {
  const count = useCountUp(value, 800)
  const ref   = useFadeIn(delay)
  return (
    <div className={styles.statCard} ref={ref}>
      <span className={styles.statVal} style={color ? { color } : {}}>{count}</span>
      <span className={styles.statLbl}>{label}</span>
    </div>
  )
}

// ── Threat Meter ──────────────────────────────────────────────
function ThreatMeter({ score }) {
  const [width, setWidth] = useState(0)
  const pct   = Math.round((score ?? 0) * 100)
  const color = pct >= 60 ? 'var(--red)' : pct >= 30 ? 'var(--amber)' : 'var(--green)'
  const label = pct >= 60 ? '🔴 HIGH RISK' : pct >= 30 ? '🟡 SUSPICIOUS' : '🟢 SAFE'
  useEffect(() => {
    const t = setTimeout(() => setWidth(pct), 100)
    return () => clearTimeout(t)
  }, [pct])
  return (
    <div className={styles.threatMeter}>
      <div className={styles.threatHeader}>
        <span className={styles.threatLabel}>Threat Score</span>
        <span className={styles.threatPct} style={{ color }}>{pct}%</span>
      </div>
      <div className={styles.threatBar}>
        <div className={styles.threatFill} style={{ width: `${width}%`, background: color, transition: 'width 1.2s cubic-bezier(0.25,0.46,0.45,0.94)' }} />
      </div>
      <div className={styles.threatVerdict} style={{ color }}>{label}</div>
    </div>
  )
}

// ── Scanning Overlay (skeleton shimmer) ───────────────────────
function ScanningOverlay() {
  const steps = ['Parsing URL structure...', 'Running ML model...', 'Checking VirusTotal...', 'Analysing heuristics...']
  const [step, setStep] = useState(0)
  const [progress, setProgress] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setStep(s => (s + 1) % steps.length), 700)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    const t = setInterval(() => setProgress(p => Math.min(p + 2, 90)), 80)
    return () => clearInterval(t)
  }, [])
  return (
    <div className={styles.scanOverlay}>
      <div className={styles.scanSpinner} />
      <div className={styles.scanProgressBar}>
        <div className={styles.scanProgressFill} style={{ width: `${progress}%` }} />
      </div>
      <div className={styles.scanStep}>{steps[step]}</div>
      <div className={styles.scanDots}>
        {[0,1,2].map(i => <span key={i} className={styles.dot} style={{ animationDelay: `${i*0.2}s` }} />)}
      </div>
    </div>
  )
}

// ── Charts ────────────────────────────────────────────────────
function StatsCharts({ totalScans, phishingFound, recentHistory }) {
  const safe = Math.max(0, totalScans - phishingFound)
  const pieData = [{ name:'Phishing', value:phishingFound }, { name:'Safe', value:safe }].filter(d => d.value > 0)
  const barData = [
    { name:'Total',   value:totalScans,    fill:'var(--cyan)'  },
    { name:'Threats', value:phishingFound, fill:'var(--red)'   },
    { name:'Safe',    value:safe,          fill:'var(--green)' },
  ]
  const lineData = (() => {
    if (!recentHistory?.length) return []
    const byDay = {}
    recentHistory.forEach(s => {
      const d = new Date(s.scanned_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' })
      if (!byDay[d]) byDay[d] = { date:d, scans:0, threats:0 }
      byDay[d].scans++
      if (s.verdict === 'PHISHING') byDay[d].threats++
    })
    return Object.values(byDay).slice(-7)
  })()
  const COLORS = ['#ff2d55','#00e676']
  const ref = useFadeIn(100)
  if (totalScans === 0) return null
  return (
    <div className={styles.chartsSection} ref={ref}>
      <div className={styles.chartsGrid}>
        <div className={`${styles.chartCard} ${styles.chartAnimate}`}>
          <div className={styles.chartTitle}>🥧 Scan Breakdown</div>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60} dataKey="value" paddingAngle={3} isAnimationActive={true} animationBegin={0} animationDuration={800}>
                {pieData.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
              </Pie>
              <Tooltip contentStyle={{ background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:'8px', fontSize:'11px', color:'var(--txt1)' }} />
            </PieChart>
          </ResponsiveContainer>
          <div className={styles.chartLegend}>
            <span style={{ color:'#ff2d55' }}>● Phishing: {phishingFound}</span>
            <span style={{ color:'#00e676' }}>● Safe: {safe}</span>
          </div>
        </div>
        <div className={`${styles.chartCard} ${styles.chartAnimate}`} style={{ animationDelay:'100ms' }}>
          <div className={styles.chartTitle}>📊 Summary</div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={barData} margin={{ top:5, right:5, left:-20, bottom:5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fontSize:10, fill:'var(--txt2)' }} />
              <YAxis tick={{ fontSize:10, fill:'var(--txt2)' }} allowDecimals={false} />
              <Tooltip contentStyle={{ background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:'8px', fontSize:'11px', color:'var(--txt1)' }} />
              <Bar dataKey="value" radius={[4,4,0,0]} isAnimationActive={true} animationDuration={800}>
                {barData.map((d,i) => <Cell key={i} fill={d.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        {lineData.length > 1 && (
          <div className={`${styles.chartCard} ${styles.chartWide} ${styles.chartAnimate}`} style={{ animationDelay:'200ms' }}>
            <div className={styles.chartTitle}>📈 Activity (Last 7 Days)</div>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={lineData} margin={{ top:5, right:15, left:-20, bottom:5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="date" tick={{ fontSize:9, fill:'var(--txt2)' }} />
                <YAxis tick={{ fontSize:9, fill:'var(--txt2)' }} allowDecimals={false} />
                <Tooltip contentStyle={{ background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:'8px', fontSize:'11px', color:'var(--txt1)' }} />
                <Legend wrapperStyle={{ fontSize:'10px' }} />
                <Line type="monotone" dataKey="scans" stroke="var(--cyan)" strokeWidth={2} dot={false} name="Scans" isAnimationActive={true} animationDuration={1000} />
                <Line type="monotone" dataKey="threats" stroke="var(--red)" strokeWidth={2} dot={false} name="Threats" isAnimationActive={true} animationDuration={1000} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Recent Scans ──────────────────────────────────────────────
function RecentScans({ scans }) {
  if (!scans?.length) return null
  const VERDICT_COLOR = { PHISHING:'var(--red)', SUSPICIOUS:'var(--amber)', SAFE:'var(--green)', TRUSTED:'var(--cyan)' }
  const VERDICT_ICON  = { PHISHING:'🚨', SUSPICIOUS:'⚠️', SAFE:'✅', TRUSTED:'🔵' }
  return (
    <div className={styles.recentPanel}>
      <div className="sec-lbl">🕒 Recent Activity</div>
      <div className={styles.recentList}>
        {scans.slice(0, 5).map((s, i) => (
          <div key={i} className={styles.recentItem} style={{ animationDelay: `${i * 80}ms` }}>
            <span className={styles.recentIcon}>{VERDICT_ICON[s.verdict] ?? '?'}</span>
            <span className={styles.recentUrl}>{s.url.replace(/^https?:\/\//, '').slice(0, 42)}{s.url.length > 50 ? '…' : ''}</span>
            <span className={styles.recentVerdict} style={{ color: VERDICT_COLOR[s.verdict] }}>{s.verdict}</span>
            <span className={styles.recentTime}>{new Date(s.scanned_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit', hour12:true })}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── How It Works ──────────────────────────────────────────────
function HowItWorks() {
  const steps = [
    { icon:'🔗', title:'Paste URL',    desc:'Enter any URL you want to verify' },
    { icon:'🤖', title:'ML Analysis',  desc:'Random Forest model + 6 URL features analysed' },
    { icon:'🛡️', title:'VirusTotal',  desc:'Cross-checked against 70+ threat engines' },
    { icon:'📊', title:'Result',       desc:'Verdict with full explanation & threat score' },
  ]
  return (
    <div className={styles.howItWorks}>
      <div className="sec-lbl">⚡ How It Works</div>
      <div className={styles.stepsGrid}>
        {steps.map((s, i) => (
          <div key={i} className={`${styles.stepCard} ${styles.stepHover}`} style={{ animationDelay: `${i * 100}ms` }}>
            <div className={styles.stepNum}>0{i + 1}</div>
            <div className={styles.stepIcon}>{s.icon}</div>
            <div className={styles.stepTitle}>{s.title}</div>
            <div className={styles.stepDesc}>{s.desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Quick Test ────────────────────────────────────────────────
function QuickTest({ onScan }) {
  const urls = [
    { url:'https://google.com',            label:'Google',    type:'safe'     },
    { url:'http://paypa1.com',             label:'Typosquat', type:'phishing' },
    { url:'http://amazon-verify.tk/login', label:'Phishing',  type:'phishing' },
    { url:'https://github.com',            label:'GitHub',    type:'safe'     },
  ]
  return (
    <div className={styles.quickTest}>
      <div className="sec-lbl">🧪 Quick Test</div>
      <div className={styles.quickList}>
        {urls.map((u, i) => (
          <button key={i} className={`${styles.quickBtn} ${styles[u.type]}`} onClick={() => onScan(u.url)}>
            {u.type === 'safe' ? '✅' : '🚨'} {u.label}
          </button>
        ))}
      </div>
    </div>
  )
}

// ── Ripple button ─────────────────────────────────────────────
function RippleButton({ onClick, disabled, children, className, style }) {
  const [ripples, setRipples] = useState([])
  const handleClick = (e) => {
    const btn  = e.currentTarget.getBoundingClientRect()
    const x    = e.clientX - btn.left
    const y    = e.clientY - btn.top
    const id   = Date.now()
    setRipples(r => [...r, { x, y, id }])
    setTimeout(() => setRipples(r => r.filter(rp => rp.id !== id)), 600)
    onClick?.()
  }
  return (
    <button className={`${className} ${styles.rippleBtn}`} onClick={handleClick} disabled={disabled} style={{ ...style, position:'relative', overflow:'hidden' }}>
      {children}
      {ripples.map(rp => (
        <span key={rp.id} className={styles.ripple} style={{ left: rp.x - 20, top: rp.y - 20 }} />
      ))}
    </button>
  )
}

// ── Main Dashboard ────────────────────────────────────────────
export default function Dashboard() {
  const { user } = useAuth()
  const [tab, setTab]             = useState('single')
  const [url, setUrl]             = useState('')
  const [batchText, setBatch]     = useState('')
  const [result, setResult]       = useState(null)
  const [batchResult, setBatchResult] = useState(null)
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState('')
  const [recentScans, setRecent]  = useState([])
  const [resultVisible, setResultVisible] = useState(false)

  const headerRef = useFadeIn(0)
  const welcomeRef = useFadeIn(100)

  useEffect(() => {
    api.get('/history/?page=1&limit=10')
      .then(r => setRecent(r.data?.scans || []))
      .catch(() => {})
  }, [result])

  const scanSingle = useCallback(async (overrideUrl) => {
    const target = (overrideUrl || url).trim()
    if (!target) { setError('Please enter a URL.'); return }
    setError(''); setLoading(true); setResult(null); setResultVisible(false)
    try {
      const { data } = await api.post('/scan/single', { url: target })
      setResult(data)
      setTimeout(() => setResultVisible(true), 50)
      if (!overrideUrl) setUrl('')
    } catch (e) {
      setError(e.response?.data?.detail || 'Scan failed. Please try again.')
    } finally { setLoading(false) }
  }, [url])

  const scanBatch = async () => {
    const urls = batchText.split('\n').map(u => u.trim()).filter(Boolean)
    if (!urls.length) { setError('Please enter at least one URL.'); return }
    if (urls.length > 50) { setError('Maximum 50 URLs allowed.'); return }
    setError(''); setLoading(true); setBatchResult(null)
    try {
      const { data } = await api.post('/scan/batch', { urls })
      setBatchResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Batch scan failed.')
    } finally { setLoading(false) }
  }

  const verdictColor = { PHISHING:'var(--red)', SUSPICIOUS:'var(--amber)', SAFE:'var(--green)', TRUSTED:'var(--cyan)' }

  return (
    <div className={styles.page}>

      {/* Header */}
      <div className={styles.header} ref={headerRef}>
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
            <AnimatedStat value={user?.total_scans ?? 0}   label="Scans"   delay={200} />
            <AnimatedStat value={user?.phishing_found ?? 0} label="Threats" color="var(--red)"   delay={300} />
            <AnimatedStat value={Math.max(0,(user?.total_scans??0)-(user?.phishing_found??0))} label="Safe" color="var(--green)" delay={400} />
          </div>
          <LiveClock />
        </div>
      </div>

      {/* Welcome */}
      <p className={styles.welcome} ref={welcomeRef}>
        Welcome back, <strong>{user?.name}</strong>! Paste a URL to check if it's safe.
      </p>

      {/* Charts */}
      <StatsCharts totalScans={user?.total_scans??0} phishingFound={user?.phishing_found??0} recentHistory={recentScans} />

      {/* Scan layout */}
      <div className={styles.scanLayout}>
        <div className={styles.scanLeft}>
          {/* Tabs */}
          <div className={styles.tabs}>
            {[{ id:'single', label:'🔍 Single URL' }, { id:'batch', label:'📋 Batch Scan' }].map(t => (
              <button key={t.id}
                className={`${styles.tabBtn} ${tab===t.id?styles.tabActive:''}`}
                onClick={() => { setTab(t.id); setResult(null); setBatchResult(null); setError('') }}>
                {t.label}
              </button>
            ))}
          </div>

          {/* Single scan */}
          {tab === 'single' && (
            <div className="panel">
              <div className="sec-lbl">Scan a URL</div>
              <div className={styles.inputRow}>
                <input className={`pg-input ${styles.scanInput}`} value={url}
                  onChange={e => setUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  onKeyDown={e => e.key==='Enter' && !loading && scanSingle()} />
                <RippleButton className="pg-btn sm" onClick={() => scanSingle()} disabled={loading} style={{ flexShrink:0, minWidth:80 }}>
                  {loading ? '...' : 'Scan'}
                </RippleButton>
              </div>
              {error && <div className={`error-msg ${styles.errorShake}`}>{error}</div>}
              {loading && <ScanningOverlay />}
              {result && !loading && (
                <div className={`${styles.resultWrapper} ${resultVisible ? styles.resultVisible : ''}`}>
                  <ThreatMeter score={result.final_proba} />
                  <ScanResult result={result} />
                </div>
              )}
            </div>
          )}

          {/* Batch scan */}
          {tab === 'batch' && (
            <div className="panel">
              <div className="sec-lbl">Batch Scan (one URL per line, max 50)</div>
              <textarea className={`pg-input ${styles.textarea}`}
                value={batchText} onChange={e => setBatch(e.target.value)}
                placeholder={"https://google.com\nhttp://suspicious-site.ru\nhttps://github.com"} />
              <div style={{ marginTop:12 }}>
                <RippleButton className="pg-btn sm" onClick={scanBatch} disabled={loading}>
                  {loading ? 'Scanning...' : `Scan ${batchText.split('\n').filter(l=>l.trim()).length||0} URLs`}
                </RippleButton>
              </div>
              {error && <div className="error-msg">{error}</div>}
              {loading && <ScanningOverlay />}
            </div>
          )}

          {/* Batch result */}
          {batchResult && (
            <div className={styles.batchResultAnim} style={{ marginTop:12 }}>
              <div className={styles.batchSummary}>
                {[
                  { label:'Scanned',    val:batchResult.summary.total,      color:'var(--cyan)'  },
                  { label:'Phishing',   val:batchResult.summary.phishing,   color:'var(--red)'   },
                  { label:'Suspicious', val:batchResult.summary.suspicious, color:'var(--amber)' },
                  { label:'Safe',       val:batchResult.summary.safe,       color:'var(--green)' },
                ].map(s => (
                  <div key={s.label} className={styles.summaryCard}>
                    <span className={styles.summaryVal} style={{ color:s.color }}>{s.val}</span>
                    <span className={styles.summaryLbl}>{s.label}</span>
                  </div>
                ))}
              </div>
              <div className="panel" style={{ overflowX:'auto', padding:0, marginTop:10 }}>
                <table className={styles.batchTable}>
                  <thead><tr>{['URL','Score','Verdict','Flags'].map(h=><th key={h}>{h}</th>)}</tr></thead>
                  <tbody>
                    {batchResult.results.map((r, i) => (
                      <tr key={i} className={styles.batchRow} style={{ animationDelay:`${i*50}ms` }}>
                        <td className={styles.urlCell}>{r.url.replace(/^https?:\/\//,'').slice(0,40)}</td>
                        <td style={{ color:verdictColor[r.verdict], fontWeight:700 }}>{(r.final_proba*100).toFixed(1)}%</td>
                        <td style={{ color:verdictColor[r.verdict], fontWeight:700 }}>{r.verdict}</td>
                        <td>{r.flags?.length??0}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Right sidebar */}
        <div className={styles.scanRight}>
          <RecentScans scans={recentScans} />
          <QuickTest onScan={u => { setTab('single'); setUrl(u); setResult(null); }} />
          <HowItWorks />
        </div>
      </div>

      {/* Footer */}
      <div className={styles.footer}>
        <span>Final Year Project — Divyansh Sharma</span>
        <span>Phishing URL Detection using ML · 2026</span>
      </div>
    </div>
  )
}