import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../api/client'
import styles from './Auth.module.css'

function getPasswordStrength(password) {
  let score = 0
  const checks = {
    length:    password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number:    /[0-9]/.test(password),
    special:   /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
  }
  score = Object.values(checks).filter(Boolean).length
  const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']
  const colors = ['', '#ff2d55', '#ff2d55', '#ffab00', '#00e676', '#00c8ff']
  return { score, checks, label: labels[score], color: colors[score] }
}

export default function Register() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPass, setShowPass] = useState(false)

  const onChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))
  const strength = getPasswordStrength(form.password)

  const validatePassword = (pwd) => {
    if (pwd.length < 8)           return 'Password must be at least 8 characters.'
    if (!/[A-Z]/.test(pwd))       return 'Password must contain at least one uppercase letter.'
    if (!/[0-9]/.test(pwd))       return 'Password must contain at least one number.'
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd))
                                   return 'Password must contain at least one special character (!@#$% etc).'
    return null
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (!form.name || !form.email || !form.password) { setError('Please fill in all fields.'); return }
    const pwdErr = validatePassword(form.password)
    if (pwdErr) { setError(pwdErr); return }
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return }
    setLoading(true)
    try {
      await api.post('/auth/register', {
        name: form.name, email: form.email, password: form.password
      })
      navigate('/login?registered=1')
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
            <div className={styles.logoTitle}>PhishGuard</div>
            <div className={styles.logoSub}>Create your account</div>
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
            <div style={{ position: 'relative' }}>
              <input className="pg-input" type={showPass ? 'text' : 'password'} name="password"
                placeholder="Min. 8 chars, uppercase, number, special"
                value={form.password} onChange={onChange}
                style={{ paddingRight: '44px' }} />
              <button type="button" onClick={() => setShowPass(s => !s)}
                style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                         background: 'none', border: 'none', cursor: 'pointer', fontSize: '16px',
                         color: 'var(--txt2)' }}>
                {showPass ? '🙈' : '👁️'}
              </button>
            </div>

            {/* Password strength bar */}
            {form.password.length > 0 && (
              <div style={{ marginTop: '8px' }}>
                <div style={{ display: 'flex', gap: '4px', marginBottom: '4px' }}>
                  {[1,2,3,4,5].map(i => (
                    <div key={i} style={{
                      flex: 1, height: '3px', borderRadius: '2px',
                      background: i <= strength.score ? strength.color : 'var(--border)',
                      transition: 'background 0.3s'
                    }} />
                  ))}
                </div>
                <span style={{ fontSize: '11px', color: strength.color, fontFamily: 'var(--ff-mono)' }}>
                  {strength.label}
                </span>
                {/* Requirements checklist */}
                <div style={{ marginTop: '6px', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {[
                    { key: 'length',    label: '8+ chars' },
                    { key: 'uppercase', label: 'Uppercase' },
                    { key: 'number',    label: 'Number' },
                    { key: 'special',   label: 'Special (!@#$)' },
                  ].map(req => (
                    <span key={req.key} style={{
                      fontSize: '10px', padding: '2px 7px', borderRadius: '10px',
                      fontFamily: 'var(--ff-mono)',
                      background: strength.checks[req.key] ? 'var(--green-dim)' : 'var(--red-dim)',
                      color: strength.checks[req.key] ? 'var(--green)' : 'var(--txt3)',
                      border: `1px solid ${strength.checks[req.key] ? 'rgba(0,230,118,0.2)' : 'transparent'}`,
                    }}>
                      {strength.checks[req.key] ? '✓' : '✗'} {req.label}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className={styles.field}>
            <label className="pg-label">Confirm Password</label>
            <input className="pg-input" type="password" name="confirm"
              placeholder="Repeat your password" value={form.confirm} onChange={onChange} />
            {form.confirm && (
              <div style={{ marginTop: '4px', fontSize: '11px', fontFamily: 'var(--ff-mono)',
                            color: form.password === form.confirm ? 'var(--green)' : 'var(--red)' }}>
                {form.password === form.confirm ? '✓ Passwords match' : '✗ Passwords do not match'}
              </div>
            )}
          </div>

          {error && <div className="error-msg">{error}</div>}

          <button className="pg-btn" type="submit" disabled={loading || strength.score < 4}>
            {loading ? 'Creating account...' : 'Create Account'}
          </button>
          {strength.score < 4 && form.password.length > 0 && (
            <div style={{ fontSize: '11px', color: 'var(--txt3)', textAlign: 'center',
                          fontFamily: 'var(--ff-mono)', marginTop: '4px' }}>
              Password too weak to submit
            </div>
          )}
        </form>

        <div className={styles.switchText}>
          Already have an account?{' '}
          <Link to="/login" className={styles.switchLink}>Sign in</Link>
        </div>
      </div>
    </div>
  )
}
