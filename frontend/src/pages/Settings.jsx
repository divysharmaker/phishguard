import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'
import styles from './Auth.module.css'

export default function Settings() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [showConfirm, setShowConfirm] = useState(false)
  const [confirmText, setConfirmText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleDelete = async () => {
    if (confirmText !== 'DELETE') {
      setError('Please type DELETE to confirm')
      return
    }
    setLoading(true)
    try {
      await api.delete('/auth/delete-account')
      logout('Your account has been deleted.')
      navigate('/login')
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to delete account')
    } finally { setLoading(false) }
  }

  return (
    <div style={{ maxWidth: '500px', margin: '0 auto' }}>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--txt1)', margin: 0 }}>⚙️ Account Settings</h2>
        <p style={{ fontSize: '12px', color: 'var(--txt3)', marginTop: '4px', fontFamily: 'var(--ff-mono)' }}>Manage your account preferences</p>
      </div>

      {/* Account Info */}
      <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '12px', padding: '20px', marginBottom: '16px' }}>
        <div style={{ fontSize: '11px', color: 'var(--cyan)', fontFamily: 'var(--ff-mono)', letterSpacing: '2px', marginBottom: '14px' }}>ACCOUNT INFO</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {[
            { label: 'Name', value: user?.name },
            { label: 'Email', value: user?.email },
            { label: 'Total Scans', value: user?.total_scans ?? 0 },
            { label: 'Threats Found', value: user?.phishing_found ?? 0 },
          ].map(item => (
            <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '12px', color: 'var(--txt2)', fontFamily: 'var(--ff-mono)' }}>{item.label}</span>
              <span style={{ fontSize: '13px', color: 'var(--txt1)', fontWeight: 500 }}>{item.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Danger Zone */}
      <div style={{ background: 'var(--bg-panel)', border: '1px solid rgba(255,45,85,0.3)', borderRadius: '12px', padding: '20px' }}>
        <div style={{ fontSize: '11px', color: 'var(--red)', fontFamily: 'var(--ff-mono)', letterSpacing: '2px', marginBottom: '12px' }}>⚠️ DANGER ZONE</div>
        <p style={{ fontSize: '13px', color: 'var(--txt2)', marginBottom: '14px', lineHeight: 1.5 }}>
          Deleting your account will permanently remove all your data including scan history. This action cannot be undone.
        </p>

        {!showConfirm ? (
          <button
            onClick={() => setShowConfirm(true)}
            style={{ padding: '10px 20px', background: 'var(--red-dim)', border: '1px solid rgba(255,45,85,0.4)', borderRadius: '10px', color: 'var(--red)', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}>
            🗑️ Delete My Account
          </button>
        ) : (
          <div>
            <p style={{ fontSize: '12px', color: 'var(--red)', marginBottom: '10px', fontFamily: 'var(--ff-mono)' }}>
              Type <strong>DELETE</strong> to confirm:
            </p>
            <input
              className="pg-input"
              placeholder="Type DELETE here"
              value={confirmText}
              onChange={e => setConfirmText(e.target.value)}
              style={{ marginBottom: '10px' }}
            />
            {error && <div className="error-msg" style={{ marginBottom: '10px' }}>{error}</div>}
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={handleDelete}
                disabled={loading}
                style={{ flex: 1, padding: '10px', background: 'var(--red)', border: 'none', borderRadius: '10px', color: 'white', fontSize: '13px', fontWeight: 600, cursor: 'pointer', opacity: loading ? 0.5 : 1 }}>
                {loading ? 'Deleting...' : '🗑️ Permanently Delete'}
              </button>
              <button
                onClick={() => { setShowConfirm(false); setConfirmText(''); setError('') }}
                style={{ padding: '10px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', color: 'var(--txt2)', fontSize: '13px', cursor: 'pointer' }}>
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
