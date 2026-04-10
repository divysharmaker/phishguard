import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import styles from './Auth.module.css'

export default function Login() {
  const { login }   = useAuth()
  const navigate    = useNavigate()
  const [form, setForm]   = useState({ email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const onChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (!form.email || !form.password) { setError('Please fill in all fields.'); return }
    setLoading(true)
    try {
      const { data } = await api.post('/auth/login', form)
      login(data.token, data.user)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.authPage}>
      <div className={styles.authCard}>
        {/* Logo */}
        <div className={styles.logo}>
          <div className={styles.logoIcon}>🛡️</div>
          <div>
            <div className={styles.logoTitle}>PHISHGUARD AI</div>
            <div className={styles.logoSub}>THREAT DETECTION SYSTEM</div>
          </div>
        </div>

        <div className={styles.formTitle}>Sign in to your account</div>

        <form onSubmit={onSubmit} className={styles.form}>
          <div className={styles.field}>
            <label className="pg-label">Email Address</label>
            <input
              className="pg-input"
              type="email" name="email"
              placeholder="you@example.com"
              value={form.email} onChange={onChange}
              autoComplete="email"
            />
          </div>

          <div className={styles.field}>
            <label className="pg-label">Password</label>
            <input
              className="pg-input"
              type="password" name="password"
              placeholder="Enter your password"
              value={form.password} onChange={onChange}
              autoComplete="current-password"
            />
          </div>

          {error && <div className="error-msg">{error}</div>}

          <button className="pg-btn" type="submit" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className={styles.switchText}>
          Don't have an account?{' '}
          <Link to="/register" className={styles.switchLink}>Create one</Link>
        </div>
      </div>
    </div>
  )
}
