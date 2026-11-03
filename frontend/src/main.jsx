import { StrictMode, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import Login from './Login.jsx'

// apply the saved theme now, so the login screen matches the dashboard
try { document.documentElement.setAttribute("data-theme", localStorage.getItem("og-theme") || "dark") } catch { /* private mode */ }

// show the login screen until an analyst signs in; remember them across reloads
function Root() {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("og-user")) } catch { return null }
  })

  const login = (u) => {
    try { localStorage.setItem("og-user", JSON.stringify(u)) } catch { /* private mode */ }
    setUser(u)
  }
  const logout = () => {
    try { localStorage.removeItem("og-user") } catch { /* private mode */ }
    setUser(null)
  }

  return user ? <App user={user} onLogout={logout} onUserChange={login} /> : <Login onLogin={login} />
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Root />
  </StrictMode>,
)
