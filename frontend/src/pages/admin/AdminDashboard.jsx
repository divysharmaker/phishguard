import { useState, useEffect } from 'react'
import api from '../../api/client'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'

const VERDICT_COLOR = { PHISHING: '#ff2d55', SUSPICIOUS: '#ffab00', SAFE: '#00e676', TRUSTED: '#00c8ff' }

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', hour12: true })
}

export default function AdminDashboard() {
  const [users,        setUsers]        = useState([])
  const [stats,        setStats]        = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [selectedUser, setSelectedUser] = useState(null)
  const [userScans,    setUserScans]    = useState([])
  const [scansLoading, setScansLoading] = useState(false)
  const [search,       setSearch]       = useState('')
  const [activeTab,    setActiveTab]    = useState('users')

  useEffect(() => { fetchData() }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [u, s] = await Promise.all([api.get('/auth/admin/users'), api.get('/auth/admin/stats')])
      setUsers(u.data); setStats(s.data)
    } catch (e) { console.error(e) }
    setLoading(false)
  }

  const deleteUser = async (id, name) => {
    if (!window.confirm(`Delete "${name}" and all their data?`)) return
    await api.delete(`/auth/admin/users/${id}`)
    fetchData()
    if (selectedUser?.id === id) { setSelectedUser(null); setActiveTab('users') }
  }

  const toggleUser = async (id) => {
    const res = await api.patch(`/auth/admin/users/${id}/toggle`)
    setUsers(u => u.map(x => x.id === id ? { ...x, is_active: res.data.is_active } : x))
  }

  const viewUserScans = async (user) => {
    setSelectedUser(user); setScansLoading(true); setActiveTab('scans')
    try {
      const res = await api.get(`/auth/admin/user/${user.id}/scans`)
      setUserScans(res.data)
    } catch { setUserScans([]) }
    setScansLoading(false)
  }

  const filteredUsers = users.filter(u =>
    u.role !== 'admin' &&
    (u.name.toLowerCase().includes(search.toLowerCase()) ||
     u.email.toLowerCase().includes(search.toLowerCase()))
  )

  const pieData = stats ? [
    { name: 'Phishing', value: stats.total_phishing },
    { name: 'Safe', value: stats.total_scans - stats.total_phishing },
  ] : []

  const barData = stats ? [
    { name: 'Users', value: stats.total_users },
    { name: 'Active', value: stats.active_users },
    { name: 'Scans', value: stats.total_scans },
    { name: 'Threats', value: stats.total_phishing },
  ] : []

  if (loading) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px' }}><div className="spinner" /></div>

  return (
    <div>
      {/* Title */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--purple)', margin: 0 }}>👑 Admin Dashboard</h1>
        <p style={{ fontSize: '12px', color: 'var(--txt3)', marginTop: '4px', fontFamily: 'var(--ff-mono)' }}>Manage users, view stats and scan activity</p>
      </div>

      {/* Stats */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '10px', marginBottom: '20px' }}>
          {[
            { label: 'Total Users', value: stats.total_users, color: 'var(--purple)', icon: '👥' },
            { label: 'Active Users', value: stats.active_users, color: 'var(--green)', icon: '✅' },
            { label: 'Total Scans', value: stats.total_scans, color: 'var(--cyan)', icon: '🔍' },
            { label: 'Threats', value: stats.total_phishing, color: 'var(--red)', icon: '🚨' },
          ].map(s => (
            <div key={s.label} style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '12px', padding: '14px', textAlign: 'center' }}>
              <div style={{ fontSize: '20px', marginBottom: '4px' }}>{s.icon}</div>
              <div style={{ fontSize: '22px', fontWeight: 700, color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
              <div style={{ fontSize: '10px', color: 'var(--txt3)', fontFamily: 'monospace', marginTop: '2px' }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Charts */}
      {stats && stats.total_scans > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px', marginBottom: '20px' }}>
          <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '12px', padding: '14px' }}>
            <div style={{ fontSize: '11px', color: 'var(--txt2)', fontFamily: 'monospace', marginBottom: '8px' }}>Scan Distribution</div>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={35} outerRadius={55} dataKey="value">
                  <Cell fill="#ff2d55" /><Cell fill="#00e676" />
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '11px' }} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', fontSize: '10px', fontFamily: 'monospace' }}>
              <span style={{ color: '#ff2d55' }}>● Phishing: {stats.total_phishing}</span>
              <span style={{ color: '#00e676' }}>● Safe: {stats.total_scans - stats.total_phishing}</span>
            </div>
          </div>
          <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '12px', padding: '14px' }}>
            <div style={{ fontSize: '11px', color: 'var(--txt2)', fontFamily: 'monospace', marginBottom: '8px' }}>Platform Overview</div>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={barData} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--txt2)' }} />
                <YAxis tick={{ fontSize: 9, fill: 'var(--txt2)' }} />
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '11px' }} />
                <Bar dataKey="value" fill="var(--purple)" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '14px', flexWrap: 'wrap' }}>
        {[
          { key: 'users', label: `👥 Users (${filteredUsers.length})` },
          { key: 'scans', label: selectedUser ? `🔍 ${selectedUser.name}'s Scans` : '🔍 User Scans' },
        ].map(t => (
          <button key={t.key} onClick={() => setActiveTab(t.key)} style={{
            padding: '7px 14px', borderRadius: '8px', border: '1px solid',
            borderColor: activeTab === t.key ? 'var(--purple)' : 'var(--border)',
            background: activeTab === t.key ? 'rgba(179,136,255,0.1)' : 'var(--bg-card)',
            color: activeTab === t.key ? 'var(--purple)' : 'var(--txt2)',
            fontSize: '12px', fontWeight: 600, cursor: 'pointer',
          }}>{t.label}</button>
        ))}
        <button onClick={fetchData} style={{ marginLeft: 'auto', padding: '7px 12px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--txt2)', fontSize: '12px', cursor: 'pointer' }}>
          🔄 Refresh
        </button>
      </div>

      {/* Users Table */}
      {activeTab === 'users' && (
        <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '12px', overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <input className="pg-input" placeholder="Search by name or email..."
              value={search} onChange={e => setSearch(e.target.value)}
              style={{ maxWidth: '350px', height: '36px', padding: '0 12px' }} />
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ background: 'var(--bg-card)' }}>
                  {['User', 'Email', 'Status', 'Scans', 'Threats', 'Last Login', 'Joined', 'Actions'].map(h => (
                    <th key={h} style={{ padding: '10px 12px', textAlign: 'left', fontSize: '10px', fontWeight: 700, color: 'var(--txt2)', letterSpacing: '0.5px', whiteSpace: 'nowrap', fontFamily: 'monospace', borderBottom: '1px solid var(--border)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredUsers.length === 0 ? (
                  <tr><td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: 'var(--txt3)' }}>No users found</td></tr>
                ) : filteredUsers.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid var(--border)' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'var(--cyan-dim)', border: '1px solid var(--border-hi)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 700, color: 'var(--cyan)', flexShrink: 0 }}>
                          {u.name[0].toUpperCase()}
                        </div>
                        <span style={{ color: 'var(--txt1)', fontWeight: 500 }}>{u.name}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--txt2)', fontFamily: 'monospace', fontSize: '11px' }}>{u.email}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '10px', fontWeight: 600,
                        background: u.is_active ? 'var(--green-dim)' : 'var(--red-dim)',
                        color: u.is_active ? 'var(--green)' : 'var(--red)',
                        border: `1px solid ${u.is_active ? 'rgba(0,230,118,0.2)' : 'rgba(255,45,85,0.2)'}` }}>
                        {u.is_active ? '● Active' : '○ Blocked'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--cyan)', fontFamily: 'monospace', fontWeight: 600 }}>{u.total_scans}</td>
                    <td style={{ padding: '10px 12px', color: 'var(--red)', fontFamily: 'monospace', fontWeight: 600 }}>{u.phishing_found}</td>
                    <td style={{ padding: '10px 12px', color: 'var(--txt3)', fontSize: '11px', whiteSpace: 'nowrap' }}>{formatDate(u.last_login)}</td>
                    <td style={{ padding: '10px 12px', color: 'var(--txt3)', fontSize: '11px', whiteSpace: 'nowrap' }}>{formatDate(u.created_at)}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        <button onClick={() => viewUserScans(u)} style={{ padding: '3px 7px', fontSize: '10px', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--cyan-dim)', color: 'var(--cyan)', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>🔍</button>
                        <button onClick={() => toggleUser(u.id)} style={{ padding: '3px 7px', fontSize: '10px', borderRadius: '6px', border: '1px solid var(--border)', background: u.is_active ? 'var(--amber-dim)' : 'var(--green-dim)', color: u.is_active ? 'var(--amber)' : 'var(--green)', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
                          {u.is_active ? '🔒' : '✅'}
                        </button>
                        <button onClick={() => deleteUser(u.id, u.name)} style={{ padding: '3px 7px', fontSize: '10px', borderRadius: '6px', border: '1px solid rgba(255,45,85,0.3)', background: 'var(--red-dim)', color: 'var(--red)', cursor: 'pointer', fontWeight: 600 }}>🗑️</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Scans Tab */}
      {activeTab === 'scans' && (
        <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '12px', overflow: 'hidden' }}>
          {!selectedUser ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--txt3)' }}>👆 Select a user from Users tab</div>
          ) : scansLoading ? (
            <div style={{ padding: '40px', textAlign: 'center' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>
          ) : (
            <>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--cyan-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, color: 'var(--cyan)' }}>
                  {selectedUser.name[0]}
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--txt1)' }}>{selectedUser.name}</div>
                  <div style={{ fontSize: '11px', color: 'var(--txt3)', fontFamily: 'monospace' }}>{selectedUser.email} · {userScans.length} scans</div>
                </div>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-card)' }}>
                      {['URL', 'Verdict', 'Score', 'Type', 'Scanned At'].map(h => (
                        <th key={h} style={{ padding: '10px 12px', textAlign: 'left', fontSize: '10px', fontWeight: 700, color: 'var(--txt2)', fontFamily: 'monospace', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {userScans.length === 0 ? (
                      <tr><td colSpan={5} style={{ padding: '24px', textAlign: 'center', color: 'var(--txt3)' }}>No scans</td></tr>
                    ) : userScans.map(s => (
                      <tr key={s.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '9px 12px', color: 'var(--txt1)', maxWidth: '280px', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '11px' }}>{s.url}</td>
                        <td style={{ padding: '9px 12px' }}>
                          <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '10px', fontWeight: 700, color: VERDICT_COLOR[s.verdict] || 'var(--txt2)', background: `${VERDICT_COLOR[s.verdict]}15`, border: `1px solid ${VERDICT_COLOR[s.verdict]}30` }}>
                            {s.verdict}
                          </span>
                        </td>
                        <td style={{ padding: '9px 12px', color: VERDICT_COLOR[s.verdict] || 'var(--txt2)', fontWeight: 700, fontFamily: 'monospace' }}>
                          {s.final_proba != null ? `${(s.final_proba * 100).toFixed(1)}%` : '—'}
                        </td>
                        <td style={{ padding: '9px 12px', color: 'var(--txt3)', fontFamily: 'monospace', fontSize: '10px' }}>{s.scan_type}</td>
                        <td style={{ padding: '9px 12px', color: 'var(--txt3)', fontSize: '11px', whiteSpace: 'nowrap' }}>{formatDate(s.scanned_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      <div style={{ marginTop: '24px', padding: '10px 0', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '4px' }}>
        <span style={{ fontSize: '10px', color: 'var(--txt3)', fontFamily: 'monospace' }}>PhishGuard Admin Panel</span>
        <span style={{ fontSize: '10px', color: 'var(--txt3)', fontFamily: 'monospace' }}>Final Year Project — Divyansh Sharma · 2026</span>
      </div>
    </div>
  )
}
