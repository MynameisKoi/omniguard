import { StrictMode, useState, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import Login from './Login.jsx'
import Landing from './Landing.jsx'
import { api, setToken } from './api'

// apply the saved theme now, so the login screen matches the dashboard
try { document.documentElement.setAttribute("data-theme", localStorage.getItem("og-theme") || "dark") } catch { /* private mode */ }

// the signed-in analyst, with their session token (#18). A saved login from
// before tokens existed has none, so it counts as signed out
function savedUser() {
  try {
    const u = JSON.parse(localStorage.getItem("og-user"))
    return u && u.token ? u : null
  } catch { return null }
}
const initialUser = savedUser()
setToken(initialUser?.token)

function save(u) {
  try { u ? localStorage.setItem("og-user", JSON.stringify(u)) : localStorage.removeItem("og-user") } catch { /* private mode */ }
}

// show the login screen until an analyst signs in; remember them across reloads
function Root() {
  const [user, setUser] = useState(initialUser)
  // visitors see the marketing landing first; "Sign in" swaps in the login screen
  const [showLogin, setShowLogin] = useState(false)
  const [notice, setNotice] = useState(null)

  const login = (u) => {
    setToken(u.token)
    save(u)
    setUser(u)
    setNotice(null)
  }
  // profile edits send back name / email only: keep the session token
  const updateUser = (u) => setUser(prev => {
    const next = { ...prev, ...u }
    save(next)
    return next
  })
  const signOut = () => {
    setToken(null)
    save(null)
    setUser(null)
  }
  const logout = () => {
    // the request picks up the token before signOut clears it
    api("/auth/logout", { method: "POST" }).catch(() => {})
    signOut()
    setShowLogin(false)
  }

  // any request answered "not signed in": the session expired or was ended
  useEffect(() => {
    const ended = () => {
      signOut()
      setShowLogin(true)
      setNotice("Your session ended — sign in again to continue.")
    }
    window.addEventListener("og-session-ended", ended)
    return () => window.removeEventListener("og-session-ended", ended)
  }, [])

  if (user) return <App user={user} onLogout={logout} onUserChange={updateUser} />
  return showLogin
    ? <Login onLogin={login} onBack={() => { setShowLogin(false); setNotice(null) }} notice={notice} />
    : <Landing onSignIn={() => setShowLogin(true)} />
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Root />
  </StrictMode>,
)
