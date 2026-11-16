"use client";

import React, { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import styles from '@/app/dashboard/dashboard.module.css';

const MOCK_LOGS = [
  "[SYSTEM] Initiating global telemetry stream...",
  "[ANYCAST] Routing optimization complete. PoP instances: 24 active.",
  "[HEARTBEAT] Node FRA (Frankfurt): 12ms latency, Status: OK",
  "[HEARTBEAT] Node SJC (San Jose): 8ms latency, Status: OK",
  "[HEARTBEAT] Node NRT (Tokyo): 24ms latency, Status: OK",
  "[MESH] Edge Gateway online. Listening on 0.0.0.0:443",
  "[AUDIT] 0 active chaos rules in the current deployment.",
  "[TELEMETRY] Inbound traffic: 342 req/s. Fault injection rate: 0.00%",
  "[SYSTEM] Awaiting control plane commands...",
  "[SYSTEM] Syncing with Cloudflare D1 distributed database... OK."
];

interface AuditLogItem {
  id: string;
  source: string;
  targetUrl: string;
  injectedFault: string;
  tokenHint?: string | null;
  edgeColo?: string | null;
  statusCode?: number | null;
  latencyMs?: number | null;
  executedAt: string;
}

export const RollingLogs = () => {
  const { data: session, status } = useSession();
  const isLoggedIn = status === 'authenticated' && !!session?.user;

  // State for unauthenticated mock logs
  const [mockLogs, setMockLogs] = useState<{ id: string; text: string }[]>(
    MOCK_LOGS.slice(0, 5).map((text, i) => ({ id: `init-${i}`, text }))
  );

  // State for authenticated real logs
  const [realLogs, setRealLogs] = useState<{ id: string; text: string; prefixColor?: string }[]>([]);

  // Timer for unauthenticated mock logs
  useEffect(() => {
    if (isLoggedIn) return;

    let i = 5;
    const interval = setInterval(() => {
      setMockLogs((prev) => {
        const linesToAddCount = Math.random() > 0.5 ? 2 : 1;
        const newLines = [];
        for (let j = 0; j < linesToAddCount; j++) {
          newLines.push({
            id: `log-${Date.now()}-${j}`,
            text: MOCK_LOGS[(i + j) % MOCK_LOGS.length]
          });
        }
        i += linesToAddCount;
        const combined = [...prev, ...newLines];
        if (combined.length > 12) return combined.slice(combined.length - 12);
        return combined;
      });
    }, 5000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  // Poller for authenticated real logs
  useEffect(() => {
    if (!isLoggedIn) return;

    let isMounted = true;

    const fetchLogs = async () => {
      try {
        const res = await fetch('/api/audit/logs?limit=8');
        if (!res.ok) return;
        const data = await res.json() as { success: boolean; logs: AuditLogItem[] };
        if (!isMounted || !data.success) return;

        if (data.logs.length === 0) {
          const userName = session?.user?.name || (session?.user as any)?.username || 'Developer';
          setRealLogs([
            { id: 'sys-1', text: `[SYSTEM] Authenticated as @${userName}. Edge stream connected.`, prefixColor: '#10b981' },
            { id: 'sys-2', text: '[SYSTEM] Awaiting chaos ingress traffic from Web, Agent, or CLI...', prefixColor: '#06b6d4' },
            { id: 'sys-3', text: '[HINT] Trigger an injection test on the left, or use Codex via Skill.md.', prefixColor: '#eab308' }
          ]);
          return;
        }

        const formatted = data.logs.slice().reverse().map(l => {
          const timeStr = new Date(l.executedAt).toLocaleTimeString();
          const colo = l.edgeColo || 'EDGE';
          const srcTag = l.source === 'AGENT_API' ? '[AGENT]' : l.source === 'WEB_DASHBOARD' ? '[WEB]' : '[EDGE]';
          let target = l.targetUrl || 'unknown';
          try {
            if (target.startsWith('http://') || target.startsWith('https://')) {
              target = new URL(target).hostname;
            }
          } catch {}

          let faultDesc = l.injectedFault;
          let prefixColor = '#06b6d4';

          if (l.injectedFault === '502') {
            faultDesc = '502 Bad Gateway';
            prefixColor = '#f87171';
          } else if (l.injectedFault === '504') {
            faultDesc = '504 Gateway Timeout';
            prefixColor = '#f87171';
          } else if (l.injectedFault === '429') {
            faultDesc = '429 Rate Limit';
            prefixColor = '#fbbf24';
          } else if (l.injectedFault === 'latency') {
            faultDesc = `+${l.latencyMs ?? 0}ms Latency`;
            prefixColor = '#38bdf8';
          } else if (l.injectedFault === 'TOKEN_MINTED') {
            faultDesc = 'Token Minted';
            prefixColor = '#10b981';
          } else if (l.injectedFault === 'TOKEN_REVOKED') {
            faultDesc = 'Token Revoked';
            prefixColor = '#94a3b8';
          }

          const lineText = `[${timeStr}] ${srcTag} ${colo} ➔ ${faultDesc} | ${target}`;
          return {
            id: l.id,
            text: lineText,
            prefixColor
          };
        });

        setRealLogs(formatted);
      } catch (err) {
        console.warn('Failed to load telemetry logs:', err);
      }
    };

    fetchLogs();
    const pollInterval = setInterval(fetchLogs, 4000);
    return () => {
      isMounted = false;
      clearInterval(pollInterval);
    };
  }, [isLoggedIn, session]);

  if (isLoggedIn) {
    return (
      <>
        <div className={styles.rollingLogHeader} style={{ color: '#10b981' }}>
          ● Live Account Telemetry - Real Time
        </div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {realLogs.map((log) => {
            const match = log.text.match(/^(\[.*?\])(.*)$/);
            if (!match) return <div key={log.id} className={styles.logLine}>{log.text}</div>;
            return (
              <div key={log.id} className={styles.logLine}>
                <span className={styles.logPrefix} style={{ color: log.prefixColor || '#10b981' }}>{match[1]}</span>
                {match[2]}
              </div>
            );
          })}
        </div>
      </>
    );
  }

  // Unauthenticated Guest Demo
  return (
    <>
      <div className={styles.rollingLogHeader}>Background Telemetry - View Only</div>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {mockLogs.map((log) => {
          const match = log.text.match(/^(\[.*?\])(.*)$/);
          if (!match) return <div key={log.id} className={styles.logLine}>{log.text}</div>;
          return (
            <div key={log.id} className={styles.logLine}>
              <span className={styles.logPrefix}>{match[1]}</span>
              {match[2]}
            </div>
          );
        })}
      </div>
    </>
  );
};
