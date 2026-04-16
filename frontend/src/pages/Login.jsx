import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import styles from './Auth.module.css'

// ── Forgot Password Modal ─────────────────────────────────────
function ForgotPasswordModal({ onClose }) {
  const [step, setStep]       = useState('email') // email | sent
  const [email, setEmail]     = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')

  const handleSubmit = async () => {
    if (!email.trim()) { setError('Please enter your email.'); return }
    setError(''); setLoading(true)
    try {
      await api.post('/auth/forgot-password', { email: email.trim().toLowerCase() })
      setStep('sent')
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to send reset email.')
    } finally { setLoading(false) }
  }

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modalCard} onClick={e => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <div className={styles.modalTitle}>🔑 Reset Password</div>
          <button className={styles.modalClose} onClick={onClose}>✕</button>
        </div>

        {step === 'email' ? (
          <>
            <p className={styles.modalDesc}>
              Enter your registered email address. We'll send you a password reset link.
            </p>
            <div className={styles.field} style={{ marginBottom: 16 }}>
              <label className="pg-label">Email Address</label>
              <input className="pg-input" type="email" value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com"
                onKeyDown={e => e.key === 'Enter' && handleSubmit()} />
            </div>
            {error && <div className="error-msg" style={{ marginBottom: 12 }}>{error}</div>}
            <button className="pg-btn sm" onClick={handleSubmit} disabled={loading}
              style={{ width: '100%', height: 42 }}>
              {loading ? 'Sending...' : '📧 Send Reset Link'}
            </button>
          </>
        ) : (
          <div className={styles.sentBox}>
            <div className={styles.sentIcon}>📬</div>
            <div className={styles.sentTitle}>Check Your Email!</div>
            <div className={styles.sentDesc}>
              Password reset link sent to <strong>{email}</strong>.
              <br />Link expires in <strong>30 minutes</strong>.
            </div>
            <button className="pg-btn sm ghost" onClick={onClose} style={{ marginTop: 16, width: '100%' }}>
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Login ────────────────────────────────────────────────
export default function Login() {
  const { login, logoutMsg, setLogoutMsg } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [form, setForm]           = useState({ email: '', password: '' })
  const [error, setError]         = useState('')
  const [success, setSuccess]     = useState('')
  const [loading, setLoading]     = useState(false)
  const [isAdmin, setIsAdmin]     = useState(false)
  const [showForgot, setShowForgot] = useState(false)
  const [showPass, setShowPass]   = useState(false)

  useEffect(() => {
    if (searchParams.get('registered')) setSuccess('Account created! Please sign in.')
    if (searchParams.get('reset'))      setSuccess('Password reset successfully! Please sign in.')
    if (logoutMsg) { setSuccess(logoutMsg); setLogoutMsg?.('') }
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
        setLoading(false); return
      }
      login(data.token, data.user)
      navigate(data.user.role === 'admin' ? '/admin' : '/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please try again.')
    } finally { setLoading(false) }
  }

  return (
    <div className={styles.authPage}>
      <div className={`${styles.authCard} ${styles.cardAnimate}`}>
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
            <div style={{ position: 'relative' }}>
              <input className="pg-input" type={showPass ? 'text' : 'password'} name="password"
                placeholder="Enter your password"
                value={form.password} onChange={onChange} autoComplete="current-password"
                style={{ paddingRight: '44px' }} />
              <button type="button" onClick={() => setShowPass(s => !s)}
                style={{ position:'absolute', right:'12px', top:'50%', transform:'translateY(-50%)',
                         background:'none', border:'none', cursor:'pointer', fontSize:'16px', color:'var(--txt2)' }}>
                {showPass ? '🙈' : '👁️'}
              </button>
            </div>
          </div>

          {/* Forgot password link */}
          {!isAdmin && (
            <div style={{ textAlign: 'right', marginTop: '-8px' }}>
              <button type="button" className={styles.forgotLink}
                onClick={() => setShowForgot(true)}>
                Forgot password?
              </button>
            </div>
          )}

          {success && (
            <div className="error-msg" style={{ color:'var(--green)', background:'var(--green-dim)', borderColor:'rgba(0,230,118,0.25)' }}>
              ✓ {success}
            </div>
          )}
          {error && <div className="error-msg">{error}</div>}

          <button className={`pg-btn ${isAdmin ? styles.adminBtn : ''}`} type="submit" disabled={loading}>
            {loading ? 'Signing in...' : isAdmin ? '👑 Admin Sign In' : 'Sign In →'}
          </button>
        </form>

        {!isAdmin && (
          <div className={styles.switchText}>
            Don't have an account?{' '}
            <Link to="/register" className={styles.switchLink}>Create one</Link>
          </div>
        )}
      </div>

      {showForgot && <ForgotPasswordModal onClose={() => setShowForgot(false)} />}
    </div>
  )
}