import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';
import { useWebSocket } from '../hooks/useWebSocket';
import { ServiceCard } from '../components/ServiceCard';
import type { ServiceStatus } from '../types';

export default function Services() {
  const api = useApi();
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [error, setError] = useState<string | null>(null);

  useWebSocket<{ type: string; data: ServiceStatus[] }>(
    '/ws/services',
    (msg) => { if (msg.type === 'services') setServices(msg.data); }
  );

  useEffect(() => {
    (async () => {
      try { setServices(await api.get<ServiceStatus[]>('/api/services/list')); }
      catch (e: any) { setError(e.message); }
    })();
  }, []);

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Services</h1>
      {error && <div className="error">{error}</div>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
        {services.map((s) => (
          <ServiceCard key={s.name} name={s.name} active={s.active} />
        ))}
      </div>
    </div>
  );
}
