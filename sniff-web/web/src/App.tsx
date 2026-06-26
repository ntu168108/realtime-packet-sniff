import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useCallback } from 'react';

export default function App() {
  const [token, setTok] = useState<string | null>(() => localStorage.getItem('sniff_jwt'));

  const logout = useCallback(() => {
    localStorage.removeItem('sniff_jwt');
    setTok(null);
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login onLogin={(t) => { localStorage.setItem('sniff_jwt', t); setTok(t); }} />} />
        <Route path="/*" element={token ? <Layout onLogout={logout} /> : <Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  );
}

function Login({ onLogin }: { onLogin: (t: string) => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setError(body.detail || `Login failed: ${r.status}`);
        return;
      }
      const body = await r.json();
      localStorage.setItem('sniff_jwt', body.token);
      onLogin(body.token);
    } catch (e: any) {
      setError(`Network error: ${e.message}`);
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <h1>SNIFF Web GUI</h1>
        {error && <div className="error">{error}</div>}
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" className="btn" style={{ width: '100%' }}>Sign in</button>
      </form>
    </div>
  );
}

function Layout({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="app-layout">
      <header className="topbar">
        <span className="logo">SNIFF</span>
        <span className="grow" />
        <span className="user">admin</span>
        <button onClick={onLogout}>Logout</button>
      </header>
      <nav className="sidebar">
        <a href="/dashboard">Dashboard</a>
      </nav>
      <main className="main">
        <div className="card">
          <h2>Layout scaffold OK</h2>
          <p>Real pages will be added in subsequent tasks.</p>
        </div>
      </main>
    </div>
  );
}