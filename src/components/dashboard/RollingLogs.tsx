"use client";

import React, { useState, useEffect, useRef } from 'react';
import { useSession } from 'next-auth/react';
import styles from '@/app/dashboard/dashboard.module.css';

const FABRIC_TELEMETRY_MSGS = [
  "[ANYCAST] Routing optimization verified. Active edge PoPs: 285+ locations.",
  "[HEARTBEAT] Node SJC (San Jose): 8ms latency, Cloudflare D1 Primary OK.",
  "[HEARTBEAT] Node LAX (Los Angeles): 11ms latency, Edge Cluster Active.",
  "[HEARTBEAT] Node FRA (Frankfurt): 14ms latency, Edge Replica in-sync.",
  "[HEARTBEAT] Node NRT (Tokyo): 26ms latency, Regional Mesh OK.",
  "[FABRIC] Zero-trust TLS session validated with edge proxy gateway.",
  "[MESH] Chaos engine listening on global edge anycast network.",
  "[TELEMETRY] Upstream health probe: 99.98% availability across nodes."
];

interface FaultPolicy {
  fault: string;
  latency?: number;
  jitter?: number;
  packetLoss?: number;
  distribution?: string;
  mutilationStrategy?: string;
}

interface AuditLogItem {
  id: string;
  source: string;
  targetUrl: string;
  injectedFault: string;
  faultPolicy?: FaultPolicy;
  tokenHint?: string | null;
  edgeColo?: string | null;
  statusCode?: number | null;
  latencyMs?: number | null;
  rayId?: string | null;
  executedAt: string;
}

interface StreamLine {
  key: string;
  text: string;
  prefixColor?: string;
}

function formatTwoDigits(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function formatAuditTime(isoStr?: string): string {
  const d = isoStr ? new Date(isoStr) : new Date();
  if (isNaN(d.getTime())) return new Date().toTimeString().split(' ')[0];
  return `${formatTwoDigits(d.getHours())}:${formatTwoDigits(d.getMinutes())}:${formatTwoDigits(d.getSeconds())}`;
}

function formatAuditItemToText(item: AuditLogItem): { text: string; prefixColor: string } {
  const timeStr = formatAuditTime(item.executedAt);
  const colo = item.edgeColo && item.edgeColo !== 'UNKNOWN' && item.edgeColo !== 'ANYCAST' && item.edgeColo !== 'GLOBAL-EDGE'
    ? item.edgeColo
    : (item.rayId && item.rayId.includes('-') ? item.rayId.split('-')[1]?.toUpperCase() : 'EDGE');

  const srcTag = item.source === 'AGENT_API' ? '[AGENT]' : item.source === 'WEB_DASHBOARD' ? '[WEB]' : '[EDGE]';

  let target = item.targetUrl || '';
  if (!target || target === 'target' || target === 'https://target') {
    target = 'jsonplaceholder.typicode.com';
  } else {
    try {
      if (target.startsWith('http://') || target.startsWith('https://')) {
        target = new URL(target).hostname;
      }
    } catch {}
  }

  let faultDesc = item.injectedFault;
  let prefixColor = '#38bdf8';

  const policy = item.faultPolicy;
  if (item.injectedFault === 'TOKEN_MINTED') {
    faultDesc = 'Token Minted';
    prefixColor = '#10b981';
  } else if (item.injectedFault === 'TOKEN_REVOKED') {
    faultDesc = 'Token Revoked';
    prefixColor = '#94a3b8';
  } else if (item.injectedFault === 'PASSTHROUGH' || item.injectedFault === 'FAIL_OPEN') {
    faultDesc = 'Policy Passthrough (Fail-Open)';
    prefixColor = '#10b981';
  } else if (item.injectedFault === '502' || policy?.fault === '502') {
    faultDesc = '502 Bad Gateway';
    prefixColor = '#f87171';
  } else if (item.injectedFault === '504' || policy?.fault === '504') {
    faultDesc = '504 Gateway Timeout';
    prefixColor = '#f87171';
  } else if (item.injectedFault === '429' || policy?.fault === '429') {
    faultDesc = '429 Rate Limit';
    prefixColor = '#fbbf24';
  } else if (item.injectedFault === '444' || policy?.fault === '444') {
    faultDesc = '444 No Response';
    prefixColor = '#f87171';
  } else if (item.injectedFault === 'latency' || policy?.fault === 'latency') {
    const lat = policy?.latency ?? item.latencyMs;
    const jit = policy?.jitter ?? 0;
    const drop = policy?.packetLoss ?? 0;
    const mut = policy?.mutilationStrategy && policy.mutilationStrategy !== 'None' ? `[${policy.mutilationStrategy}]` : '';

    if (typeof lat === 'number' && lat > 0) {
      faultDesc = `+${lat}ms Latency${jit > 0 ? ` (±${jit}ms)` : ''}${drop > 0 ? ` [Drop: ${drop}%]` : ''}${mut ? ` ${mut}` : ''}`;
    } else if (drop > 0) {
      faultDesc = `Packet Drop [${drop}%]${mut ? ` ${mut}` : ''}`;
    } else {
      faultDesc = `Normal Ingress${mut ? ` ${mut}` : ''}`;
    }
    prefixColor = '#06b6d4';
  }

  return {
    text: `[${timeStr}] ${srcTag} ${colo} ➔ ${faultDesc} | ${target}`,
    prefixColor
  };
}

export const RollingLogs = () => {
  const { data: session, status } = useSession();
  const isLoggedIn = status === 'authenticated' && !!session?.user;

  // Stream state
  const [stream, setStream] = useState<StreamLine[]>([]);
  const knownLogIdsRef = useRef<Set<string>>(new Set());
  const pendingLogsRef = useRef<AuditLogItem[]>([]);
  const fabricIndexRef = useRef(0);
  const isInitialFetchRef = useRef(true);

  // Initial populate for guest
  useEffect(() => {
    if (!isLoggedIn) {
      const initial = FABRIC_TELEMETRY_MSGS.slice(0, 5).map((text, i) => ({
        key: `guest-init-${i}`,
        text,
        prefixColor: '#10b981'
      }));
      setStream(initial);
      return;
    }

    const userName = session?.user?.name || (session?.user as any)?.username || 'Developer';
    setStream([
      { key: 'init-1', text: `[${formatAuditTime()}] [SYSTEM] Connected as @${userName} to Cloudflare D1 stream.`, prefixColor: '#10b981' },
      { key: 'init-2', text: `[${formatAuditTime()}] [MESH] Global anycast edge gateway online. Awaiting ingress...`, prefixColor: '#06b6d4' }
    ]);
  }, [isLoggedIn, session]);

  // Authenticated real log poller
  useEffect(() => {
    if (!isLoggedIn) return;

    let isMounted = true;

    const fetchAuditLogs = async () => {
      // Don't poll if document is hidden to conserve D1 reads
      if (typeof document !== 'undefined' && document.hidden) return;

      try {
        const res = await fetch('/api/audit/logs?limit=8');
        if (!res.ok) return;
        const data = await res.json() as { success: boolean; logs: AuditLogItem[] };
        if (!isMounted || !data.success || !Array.isArray(data.logs)) return;

        if (isInitialFetchRef.current) {
          isInitialFetchRef.current = false;
          // Mark all initially loaded logs as known so we don't replay them one by one
          knownLogIdsRef.current = new Set(data.logs.map(l => l.id));

          if (data.logs.length > 0) {
            // Render latest logs immediately on the screen
            const userName = session?.user?.name || (session?.user as any)?.username || 'Developer';
            const recentLines = data.logs.slice(0, 6).reverse().map(item => {
              const formatted = formatAuditItemToText(item);
              return {
                key: `init-real-${item.id}`,
                text: formatted.text,
                prefixColor: formatted.prefixColor
              };
            });
            setStream([
              { key: 'init-0', text: `[${formatAuditTime()}] [SYSTEM] Connected as @${userName} to Cloudflare D1 stream.`, prefixColor: '#10b981' },
              ...recentLines
            ]);
          }
          return;
        }

        // Subsequent polls: Queue only newly arrived logs
        const newItems: AuditLogItem[] = [];
        for (const log of data.logs) {
          if (!knownLogIdsRef.current.has(log.id)) {
            knownLogIdsRef.current.add(log.id);
            newItems.push(log);
          }
        }

        if (newItems.length > 0) {
          // Push newest to pending queue (oldest first to roll in chronologically)
          pendingLogsRef.current = [...pendingLogsRef.current, ...newItems.reverse()];
        }
      } catch (err) {
        console.warn('Telemetry fetch silent warning:', err);
      }
    };

    fetchAuditLogs();
    const pollTimer = setInterval(fetchAuditLogs, 4000);

    const handleVisibilityChange = () => {
      if (!document.hidden) {
        fetchAuditLogs();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      isMounted = false;
      clearInterval(pollTimer);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [isLoggedIn, session]);

  // Smooth rolling ticker loop (Runs for both Guest & Authenticated)
  useEffect(() => {
    const rollTimer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;

      setStream((prev) => {
        let nextLine: StreamLine;

        if (isLoggedIn) {
          // Check if there are real logs waiting in queue
          if (pendingLogsRef.current.length > 0) {
            const nextItem = pendingLogsRef.current.shift()!;
            const formatted = formatAuditItemToText(nextItem);
            nextLine = {
              key: `real-${nextItem.id}-${Date.now()}`,
              text: formatted.text,
              prefixColor: formatted.prefixColor
            };
          } else {
            // Heartbeat/fabric telemetry pulse to keep terminal alive
            const fabricMsg = FABRIC_TELEMETRY_MSGS[fabricIndexRef.current % FABRIC_TELEMETRY_MSGS.length];
            fabricIndexRef.current++;
            nextLine = {
              key: `fabric-${Date.now()}`,
              text: `[${formatAuditTime()}] ${fabricMsg}`,
              prefixColor: '#64748b'
            };
          }
        } else {
          // Guest mode ticker
          const msg = FABRIC_TELEMETRY_MSGS[fabricIndexRef.current % FABRIC_TELEMETRY_MSGS.length];
          fabricIndexRef.current++;
          nextLine = {
            key: `guest-${Date.now()}`,
            text: msg,
            prefixColor: '#10b981'
          };
        }

        const nextStream = [...prev, nextLine];
        return nextStream.length > 11 ? nextStream.slice(nextStream.length - 11) : nextStream;
      });
    }, 3800);

    return () => clearInterval(rollTimer);
  }, [isLoggedIn]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {stream.map((log) => {
        const match = log.text.match(/^(\[.*?\])(.*)$/);
        if (!match) {
          return (
            <div key={log.key} className={styles.logLine}>
              {log.text}
            </div>
          );
        }
        return (
          <div key={log.key} className={styles.logLine}>
            <span className={styles.logPrefix} style={{ color: log.prefixColor || '#10b981' }}>
              {match[1]}
            </span>
            {match[2]}
          </div>
        );
      })}
    </div>
  );
};
