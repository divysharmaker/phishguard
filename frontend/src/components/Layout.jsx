import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import styles from './Layout.module.css'

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate('/login') }

  return (
    <div className={styles.shell}>
      {/* ── Navbar ── */}
      <nav className={styles.nav}>
        <div className={styles.navLeft}>
          <div className={styles.navLogo}>
            <span className={styles.navIcon}>🛡️</span>
            <span className={styles.navTitle}>PHISHGUARD AI</span>
          </div>
          <div className={styles.navLinks}>
            <NavLink to="/dashboard"
              className={({ isActive }) => `${styles.navLink} ${isActive ? styles.active : ''}`}>
              Scanner
            </NavLink>
            <NavLink to="/history"
              className={({ isActive }) => `${styles.navLink} ${isActive ? styles.active : ''}`}>
              History
            </NavLink>
          </div>
        </div>

        <div className={styles.navRight}>
          <div className={styles.userInfo}>
            <div className={styles.userAvatar}>{user?.name?.[0]?.toUpperCase() || 'U'}</div>
            <div className={styles.userDetails}>
              <span className={styles.userName}>{user?.name}</span>
              <span className={styles.userEmail}>{user?.email}</span>
            </div>
          </div>
          <button className={`pg-btn ghost sm ${styles.logoutBtn}`} onClick={handleLogout}>
            Logout
          </button>
        </div>
      </nav>

      {/* ── Page content ── */}
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  )
}
