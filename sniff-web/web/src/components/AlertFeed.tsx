import React, { useState } from 'react';
import type { AlertItem } from '../types';

interface AlertFeedProps {
  alerts: AlertItem[];
  /** When true, the component shows a transient toast on copy. */
  onCopy?: (alert_id: string) => void;
}

/**
 * Compact alert list with copy-to-clipboard.
 * - Sorted newest-first (assumes server appends in order).
 * - Renders a one-shot "copied" pill on each row for 1s.
 */
export function AlertFeed({ alerts, onCopy }: AlertFeedProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!alerts || alerts.length === 0) {
    return <div className="muted" style={{ padding: 8 }}>No alerts yet.</div>;
  }

  async function copyId(alert_id: string) {
    try {
      await navigator.clipboard.writeText(alert_id);
    } catch {
      // Clipboard API blocked — fall back to a text-area selection.
      const ta = document.createElement('textarea');
      ta.value = alert_id;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch { /* swallow */ }
      document.body.removeChild(ta);
    }
    setCopiedId(alert_id);
    setTimeout(() => setCopiedId((cur) => (cur === alert_id ? null : cur)), 1000);
    onCopy?.(alert_id);
  }

  // newest first
  const items = [...alerts].reverse();

  return (
    <div className="alert-feed">
      {items.map((a) => {
        const ts = a.received_at ?? a.ts_sec ?? 0;
        const when = ts ? new Date(ts * 1000).toLocaleTimeString() : '—';
        const flow = [a.src, a.dst].filter(Boolean).join(' → ') || a.proto || '';
        const prio = (a.priority || 'medium').toLowerCase();
        return (
          <div className="alert-row" key={a.alert_id || `${a.label}-${ts}`}>
            <div className="ts">{when}</div>
            <div>
              <span className={`pill ${prio}`}>{prio}</span>
            </div>
            <div className="label">{a.label}</div>
            <div className="flow">{flow}</div>
            <button
              type="button"
              className={`btn ghost copy ${copiedId === a.alert_id ? 'copied' : ''}`}
              onClick={() => copyId(a.alert_id)}
              title={a.alert_id}
            >
              {copiedId === a.alert_id ? 'copied' : 'copy id'}
            </button>
          </div>
        );
      })}
    </div>
  );
}
