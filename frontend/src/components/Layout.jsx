import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useState, useEffect } from 'react'
import styles from './Layout.module.css'

function getAutoTheme() {
  const h = new Date().getHours()
  return (h >= 6 && h < 18) ? 'light' : 'dark'
}

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [theme, setTheme]               = useState(() => localStorage.getItem('pg_theme') || getAutoTheme())
  const [manualOverride, setManual]     = useState(() => !!localStorage.getItem('pg_theme'))
  const [menuOpen, setMenuOpen]         = useState(false)

  useEffect(() => {
    if (manualOverride) return
    const interval = setInterval(() => {
      const auto = getAutoTheme()
      setTheme(auto)
      document.documentElement.setAttribute('data-theme', auto)
    }, 60000)
    return () => clearInterval(interval)
  }, [manualOverride])

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    if (manualOverride) localStorage.setItem('pg_theme', theme)
    else localStorage.removeItem('pg_theme')
  }, [theme, manualOverride])

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next); setManual(true)
    localStorage.setItem('pg_theme', next)
  }

  const handleLogout = () => { logout(); navigate('/login') }

  const navLinks = [
    { to: '/dashboard', label: 'Scanner', icon: '🔍' },
    { to: '/history',   label: 'History', icon: '📋' },
    { to: '/about',     label: 'Model',   icon: '🧠' },
    { to: '/settings',  label: 'Settings',icon: '⚙️' },
  ]

  return (
    <div className={styles.shell}>
      <nav className={styles.nav}>
        <div className={styles.navLeft}>
          <div className={styles.navLogo}>
            <span className={styles.navIcon}>🛡️</span>
            <span className={styles.navTitle}>PhishGuard</span>
          </div>
          <div className={styles.navLinks}>
            {navLinks.map(l => (
              <NavLink key={l.to} to={l.to}
                className={({ isActive }) => `${styles.navLink} ${isActive ? styles.active : ''}`}>
                <span className={styles.linkIcon}>{l.icon}</span>
                <span className={styles.linkLabel}>{l.label}</span>
              </NavLink>
            ))}
          </div>
        </div>

        <div className={styles.navRight}>
          <button onClick={toggleTheme} className={styles.themeBtn} title="Toggle theme">
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
          <div className={styles.userAvatar}>{user?.name?.[0]?.toUpperCase() || 'U'}</div>
          <span className={styles.userName}>{user?.name}</span>
          <button className={`pg-btn ghost sm ${styles.logoutBtn}`} onClick={handleLogout}>
            Logout
          </button>
        </div>
      </nav>
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  )
}