import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react'
import api from '../api/client'

const AuthContext = createContext(null)

const INACTIVITY_LIMIT = 30 * 60 * 1000 // 30 minutes

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const s = localStorage.getItem('pg_user')
    return s ? JSON.parse(s) : null
  })
  const [loading, setLoading] = useState(true)
  const [logoutMsg, setLogoutMsg] = useState('')
  const timerRef = useRef(null)

  const logout = useCallback((msg = '') => {
    localStorage.removeItem('pg_token')
    localStorage.removeItem('pg_user')
    setUser(null)
    if (msg) setLogoutMsg(msg)
  }, [])

  const resetTimer = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      logout('You were logged out due to inactivity.')
    }, INACTIVITY_LIMIT)
  }, [logout])

  useEffect(() => {
    const token = localStorage.getItem('pg_token')
    if (token) {
      api.get('/auth/me')
        .then(r => { setUser(r.data); localStorage.setItem('pg_user', JSON.stringify(r.data)) })
        .catch(() => { localStorage.removeItem('pg_token'); localStorage.removeItem('pg_user'); setUser(null) })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  // Auto logout on inactivity
  useEffect(() => {
    if (!user) return
    const events = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll']
    events.forEach(e => window.addEventListener(e, resetTimer))
    resetTimer()
    return () => {
      events.forEach(e => window.removeEventListener(e, resetTimer))
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [user, resetTimer])

  const login = (token, userData) => {
    localStorage.setItem('pg_token', token)
    localStorage.setItem('pg_user', JSON.stringify(userData))
    setUser(userData)
    setLogoutMsg('')
  }

  const manualLogout = () => logout('Logged out successfully.')

  return (
    <AuthContext.Provider value={{ user, login, logout: manualLogout, loading, logoutMsg, setLogoutMsg }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
