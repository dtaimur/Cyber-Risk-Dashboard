import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, post } from './api'

export type User = { username: string; display_name: string; role: string; role_label: string; permissions: string[] }

type AuthState = {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  can: (permission: string) => boolean
}

const Ctx = createContext<AuthState>(null as unknown as AuthState)
export const useAuth = () => useContext(Ctx)

/** Session lives in an HttpOnly cookie the browser manages; the client only
 *  keeps the user profile and permission list returned by /auth/me. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api<User>('/auth/me').then(setUser).catch(() => setUser(null)).finally(() => setLoading(false))
    const expired = () => setUser(null)
    window.addEventListener('auth:expired', expired)
    return () => window.removeEventListener('auth:expired', expired)
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    setUser(await post<User>('/auth/login', { username, password }))
  }, [])
  const logout = useCallback(async () => {
    try { await post('/auth/logout') } finally { setUser(null) }
  }, [])
  const can = useCallback((p: string) => !!user?.permissions.includes(p), [user])

  return <Ctx.Provider value={{ user, loading, login, logout, can }}>{children}</Ctx.Provider>
}
