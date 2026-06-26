import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';
import { useWebSocket } from '../hooks/useWebSocket';
import { CountCard } from '../components/CountCard';
import type { ServiceStatus, Counts } from '../types';

export default function Dashboard() {
  const api = useApi();
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [counts, setCounts] = useState<Counts | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { connected } = useWebSocket<{ type: string; data: ServiceStatus[] }>(
    '/ws/services',
    (msg) => {
      if (msg.type === 'services') setServices(msg.data);
    }
  );

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const s = await api.get<ServiceStatus[]>('/api/services/list');
        if (!cancelled) setServices(s);
      } catch (e: any) {
        if (!cancelled) setError(e.message);
      }
      try {
        const c = await api.get<Counts>('/api/clickhouse/counts');
        if (!cancelled) setCounts(c);
      } catch { /* counts may fail if CH down */ }
    };
    load();
    const t = setInterval(load, 10000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Dashboard</h1>
      {error && <div className="error">{error}</div>}

      <div className="card">
        <h2>Services ({connected ? 'live' : 'disconnected'})</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
          {services.map((s) => (
            <div key={s.name} className="card" style={{ padding: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono">{s.name}</span>
                <span className={`pill ${s.active ? 'active' : 'inactive'}`}>
                  {s.active ? 'active' : 'inactive'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2>ClickHouse flow counts</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 8 }}>
          <CountCard label="flows_all" value={counts?.flows_all ?? null} />
          <CountCard label="dos" value={counts?.flows_dos ?? null} />
          <CountCard label="exploits" value={counts?.flows_exploits ?? null} />
          <CountCard label="fuzzers" value={counts?.flows_fuzzers ?? null} />
          <CountCard label="generic" value={counts?.flows_generic ?? null} />
          <CountCard label="analysis" value={counts?.flows_analysis ?? null} />
          <CountCard label="reconnaissance" value={counts?.flows_reconnaissance ?? null} />
          <CountCard label="shellcode" value={counts?.flows_shellcode ?? null} />
          <CountCard label="pipeline_runs" value={counts?.pipeline_runs ?? null} />
        </div>
        {counts === null && <p className="muted">ClickHouse unreachable or empty.</p>}
      </div>
    </div>
  );
}