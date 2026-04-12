import axios from 'axios'

const api = axios.create({ 
  baseURL: 'https://phishguard-rprx.onrender.com/api'
})

// Attach JWT token to every request automatically
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('pg_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// If token expired/invalid, redirect to login
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('pg_token')
      localStorage.removeItem('pg_user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api