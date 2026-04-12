import { Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { useState, useEffect } from 'react'

function getAutoTheme() {
  const h = new Date().getHours()
  return (h >= 6 && h < 18) ? 'light' : 'dark'
}

function LiveClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return (
    <div style={{ textAlign: 'right', lineHeight: 1.3 }}>
      <div style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'monospace', color: 'var(--purple)', letterSpacing: '1px' }}>
        {time.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true })}
      </div>
      <div style={{ fontSize: '10px', color: 'var(--txt3)' }}>
        {time.toLocaleDateString('en-IN', { weekday: 'short', day: 'numeric', month: 'short' })}
      </div>
    </div>
  )
}

function WeatherWidget() {
  const [weather, setWeather] = useState(null)
  useEffect(() => {
    navigator.geolocation?.getCurrentPosition(async ({ coords }) => {
      try {
        const res = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${coords.latitude}&longitude=${coords.longitude}&current_weather=true`)
        const data = await res.json()
        const codes = { 0: '☀️', 1: '🌤️', 2: '⛅', 3: '☁️', 61: '🌧️', 80: '🌧️', 95: '⛈️' }
        setWeather({ temp: Math.round(data.current_weather.temperature), icon: codes[data.current_weather.weathercode] || '🌡️' })
      } catch {}
    })
  }, [])
  if (!weather) return null
  return <div style={{ fontSize: '12px', color: 'var(--txt2)' }}>{weather.icon} {weather.temp}°C</div>
}

export default function AdminLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [theme, setTheme] = useState(() => localStorage.getItem('pg_theme') || getAutoTheme())

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next); localStorage.setItem('pg_theme', next)
  }

  const handleLogout = () => { logout(); navigate('/login') }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-base)' }}>
      <nav style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 16px', height: '52px',
        background: 'var(--bg-panel)',
        borderBottom: '2px solid rgba(179,136,255,0.3)',
        position: 'sticky', top: 0, zIndex: 100, gap: '8px', flexWrap: 'nowrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
          <span style={{ fontSize: '16px' }}>👑</span>
          <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--purple)', letterSpacing: '0.5px', whiteSpace: 'nowrap' }}>Admin Panel</span>
          <span style={{ fontSize: '10px', background: 'rgba(179,136,255,0.15)', color: 'var(--purple)', padding: '2px 7px', borderRadius: '10px', border: '1px solid rgba(179,136,255,0.3)', whiteSpace: 'nowrap' }}>
            PhishGuard
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
          <WeatherWidget />
          <LiveClock />
          <button onClick={toggleTheme} style={{ width: '26px', height: '26px', borderRadius: '50%', background: 'var(--bg-card)', border: '1px solid var(--border)', cursor: 'pointer', fontSize: '12px', flexShrink: 0 }}>
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
          <span style={{ fontSize: '11px', color: 'var(--txt2)', whiteSpace: 'nowrap', maxWidth: '80px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user?.name}</span>
          <button onClick={handleLogout} style={{ padding: '4px 10px', background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', borderRadius: '8px', color: 'var(--red)', fontSize: '11px', cursor: 'pointer', fontWeight: 600, flexShrink: 0, whiteSpace: 'nowrap' }}>
            Logout
          </button>
        </div>
      </nav>

      <main style={{ flex: 1, padding: '16px', maxWidth: '1280px', width: '100%', margin: '0 auto', boxSizing: 'border-box' }}>
        <Outlet />
      </main>
    </div>
  )
}
