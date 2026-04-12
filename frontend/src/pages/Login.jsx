import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import styles from './Auth.module.css'

export default function Login() {
  const { login, logoutMsg, setLogoutMsg } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [form, setForm]       = useState({ email: '', password: '' })
  const [error, setError]     = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)
  const [isAdmin, setIsAdmin] = useState(false)

  useEffect(() => {
    if (searchParams.get('registered')) setSuccess('Account created! Please sign in.')
    if (logoutMsg) { setSuccess(logoutMsg); setLogoutMsg('') }
  }, [])

  const onChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(''); setSuccess('')
    if (!form.email || !form.password) { setError('Please fill in all fields.'); return }
    setLoading(true)
    try {
      const { data } = await api.post('/auth/login', form)
      if (isAdmin && data.user.role !== 'admin') {
        setError('This account does not have admin privileges.')
        setLoading(false)
        return
      }
      login(data.token, data.user)
      navigate(data.user.role === 'admin' ? '/admin' : '/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please try again.')
    } finally { setLoading(false) }
  }

  return (
    <div className={styles.authPage}>
      <div className={styles.authCard}>
        <div className={styles.logo}>
          <div className={styles.logoIcon}>{isAdmin ? '👑' : '🛡️'}</div>
          <div>
            <div className={styles.logoTitle}>PhishGuard {isAdmin ? 'Admin' : ''}</div>
            <div className={styles.logoSub}>{isAdmin ? 'Admin Control Panel' : 'Threat Detection System'}</div>
          </div>
        </div>

        <div className={styles.toggleRow}>
          <button type="button"
            className={`${styles.toggleBtn} ${!isAdmin ? styles.toggleActive : ''}`}
            onClick={() => { setIsAdmin(false); setError('') }}>
            👤 User Login
          </button>
          <button type="button"
            className={`${styles.toggleBtn} ${isAdmin ? styles.toggleActive : ''}`}
            onClick={() => { setIsAdmin(true); setError('') }}>
            👑 Admin Login
          </button>
        </div>

        {isAdmin && (
          <div className={styles.adminNote}>
            🔐 Admin access only. Unauthorized attempts are logged.
          </div>
        )}

        <form onSubmit={onSubmit} className={styles.form}>
          <div className={styles.field}>
            <label className="pg-label">Email Address</label>
            <input className="pg-input" type="email" name="email"
              placeholder={isAdmin ? 'admin@example.com' : 'you@example.com'}
              value={form.email} onChange={onChange} autoComplete="email" />
          </div>
          <div className={styles.field}>
            <label className="pg-label">Password</label>
            <input className="pg-input" type="password" name="password"
              placeholder="Enter your password"
              value={form.password} onChange={onChange} autoComplete="current-password" />
          </div>
          {success && (
            <div className="error-msg" style={{ color: 'var(--green)', background: 'var(--green-dim)', borderColor: 'rgba(0,230,118,0.25)' }}>
              ✓ {success}
            </div>
          )}
          {error && <div className="error-msg">{error}</div>}
          <button className={`pg-btn ${isAdmin ? styles.adminBtn : ''}`} type="submit" disabled={loading}>
            {loading ? 'Signing in...' : isAdmin ? '👑 Admin Sign In' : 'Sign In'}
          </button>
        </form>

        {!isAdmin && (
          <div className={styles.switchText}>
            Don't have an account?{' '}
            <Link to="/register" className={styles.switchLink}>Create one</Link>
          </div>
        )}
      </div>
    </div>
  )
}
