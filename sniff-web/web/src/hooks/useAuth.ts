import { useState, useCallback } from 'react';
import { setToken, getToken } from './useApi';

export function useAuth() {
  const [token, setTok] = useState<string | null>(getToken());

  const login = useCallback((t: string) => {
    setToken(t);
    setTok(t);
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setTok(null);
  }, []);

  return { token, isAuthenticated: !!token, login, logout };
}