import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import api from '../api/client'
import styles from './Auth.module.css'

function getPasswordStrength(password) {
  let score = 0
  const checks = {
    length:    password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    number:    /[0-9]/.test(password),
    special:   /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
  }
  score = Object.values(checks).filter(Boolean).length
  const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Strong']
  const colors = ['', '#ff2d55', '#ff2d55', '#ffab00', '#00e676']
  return { score, checks, label: labels[Math.min(score, 4)], color: colors[Math.min(score, 4)] }
}

export default function ResetPassword() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')

  const [form, setForm]     = useState({ password: '', confirm: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')
  const [success, setSuccess] = useState(false)
  const [showPass, setShowPass] = useState(false)

  useEffect(() => {
    if (!token) navigate('/login')
  }, [token])

  const strength = getPasswordStrength(form.password)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return }
    if (strength.score < 3) { setError('Password is too weak.'); return }
    setLoading(true)
    try {
      await api.post('/auth/reset-password', { token, new_password: form.password })
      setSuccess(true)
      setTimeout(() => navigate('/login?reset=1'), 2500)
    } catch (e) {
      setError(e.response?.data?.detail || 'Reset failed. Link may have expired.')
    } finally { setLoading(false) }
  }

  if (success) return (
    <div className={styles.authPage}>
      <div className={`${styles.authCard} ${styles.cardAnimate}`} style={{ textAlign:'center' }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
        <div className={styles.logoTitle}>Password Reset!</div>
        <p style={{ color:'var(--txt2)', fontSize:13, marginTop:8 }}>
          Redirecting to login...
        </p>
      </div>
    </div>
  )

  return (
    <div className={styles.authPage}>
      <div className={`${styles.authCard} ${styles.cardAnimate}`}>
        <div className={styles.logo}>
          <div className={styles.logoIcon}>🔑</div>
          <div>
            <div className={styles.logoTitle}>Reset Password</div>
            <div className={styles.logoSub}>Set your new password</div>
          </div>
        </div>

        <form onSubmit={onSubmit} className={styles.form}>
          <div className={styles.field}>
            <label className="pg-label">New Password</label>
            <div style={{ position: 'relative' }}>
              <input className="pg-input" type={showPass ? 'text' : 'password'}
                placeholder="Min. 8 chars, uppercase, number, special"
                value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                style={{ paddingRight: '44px' }} />
              <button type="button" onClick={() => setShowPass(s => !s)}
                style={{ position:'absolute', right:'12px', top:'50%', transform:'translateY(-50%)',
                         background:'none', border:'none', cursor:'pointer', fontSize:'16px', color:'var(--txt2)' }}>
                {showPass ? '🙈' : '👁️'}
              </button>
            </div>
            {form.password.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <div style={{ display:'flex', gap:4, marginBottom:4 }}>
                  {[1,2,3,4].map(i => (
                    <div key={i} style={{ flex:1, height:3, borderRadius:2,
                      background: i <= strength.score ? strength.color : 'var(--border)', transition:'background 0.3s' }} />
                  ))}
                </div>
                <span style={{ fontSize:11, color:strength.color, fontFamily:'var(--ff-mono)' }}>{strength.label}</span>
              </div>
            )}
          </div>

          <div className={styles.field}>
            <label className="pg-label">Confirm Password</label>
            <input className="pg-input" type="password"
              placeholder="Repeat your password"
              value={form.confirm} onChange={e => setForm(f => ({ ...f, confirm: e.target.value }))} />
            {form.confirm && (
              <div style={{ marginTop:4, fontSize:11, fontFamily:'var(--ff-mono)',
                color: form.password===form.confirm ? 'var(--green)' : 'var(--red)' }}>
                {form.password===form.confirm ? '✓ Passwords match' : '✗ Passwords do not match'}
              </div>
            )}
          </div>

          {error && <div className="error-msg">{error}</div>}

          <button className="pg-btn" type="submit" disabled={loading || strength.score < 3}>
            {loading ? 'Resetting...' : '🔑 Reset Password'}
          </button>
        </form>

        <div className={styles.switchText}>
          <Link to="/login" className={styles.switchLink}>← Back to Login</Link>
        </div>
      </div>
    </div>
  )
}
