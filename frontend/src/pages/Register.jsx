import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import styles from './Auth.module.css'

export default function Register() {
  const { login }   = useAuth()
  const navigate    = useNavigate()
  const [form, setForm]   = useState({ name: '', email: '', password: '', confirm: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const onChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (!form.name || !form.email || !form.password) { setError('Please fill in all fields.'); return }
    if (form.password.length < 6) { setError('Password must be at least 6 characters.'); return }
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return }
    setLoading(true)
    try {
      const { data } = await api.post('/auth/register', {
        name: form.name, email: form.email, password: form.password
      })
      login(data.token, data.user)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.authPage}>
      <div className={styles.authCard}>
        <div className={styles.logo}>
          <div className={styles.logoIcon}>🛡️</div>
          <div>
            <div className={styles.logoTitle}>PHISHGUARD AI</div>
            <div className={styles.logoSub}>CREATE YOUR ACCOUNT</div>
          </div>
        </div>

        <div className={styles.formTitle}>Create a new account</div>

        <form onSubmit={onSubmit} className={styles.form}>
          <div className={styles.field}>
            <label className="pg-label">Full Name</label>
            <input className="pg-input" type="text" name="name"
              placeholder="Your name" value={form.name} onChange={onChange} />
          </div>

          <div className={styles.field}>
            <label className="pg-label">Email Address</label>
            <input className="pg-input" type="email" name="email"
              placeholder="you@example.com" value={form.email} onChange={onChange} autoComplete="email" />
          </div>

          <div className={styles.field}>
            <label className="pg-label">Password</label>
            <input className="pg-input" type="password" name="password"
              placeholder="Min. 6 characters" value={form.password} onChange={onChange} />
          </div>

          <div className={styles.field}>
            <label className="pg-label">Confirm Password</label>
            <input className="pg-input" type="password" name="confirm"
              placeholder="Repeat your password" value={form.confirm} onChange={onChange} />
          </div>

          {error && <div className="error-msg">{error}</div>}

          <button className="pg-btn" type="submit" disabled={loading}>
            {loading ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <div className={styles.switchText}>
          Already have an account?{' '}
          <Link to="/login" className={styles.switchLink}>Sign in</Link>
        </div>
      </div>
    </div>
  )
}
