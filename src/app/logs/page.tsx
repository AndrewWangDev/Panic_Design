"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { useSession, signIn } from 'next-auth/react';
import { Activity, RefreshCw, Filter, Search, Terminal, Globe, Shield, ArrowUpRight, X } from 'lucide-react';
import CustomSelect from '@/app/dashboard/CustomSelect';
import styles from './logs.module.css';

interface FaultPolicy {
  fault: string;
  latency?: number;
  jitter?: number;
  packetLoss?: number;
  distribution?: string;
  mutilationStrategy?: string;
}

interface LogItem {
  id: string;
  source: string;
  targetUrl: string;
  injectedFault: string;
  faultPolicy?: FaultPolicy;
  tokenId?: string | null;
  tokenHint?: string | null;
  edgeColo?: string | null;
  statusCode?: number | null;
  latencyMs?: number | null;
  rayId?: string | null;
  executedAt: string;
}

interface AuditSummary {
  totalInjections: number;
  todayInjections: number;
  topTargets: Array<{ target: string; count: number }>;
  faultCounts: Record<string, number>;
}

const SOURCE_OPTIONS = [
  { value: 'ALL', label: 'All Sources' },
  { value: 'WEB_DASHBOARD', label: 'Web Console' },
  { value: 'AGENT_API', label: 'AI Agent (Codex/API)' },
  { value: 'DIRECT_DATA_PLANE', label: 'Edge Ingress Gateway' },
];

const FAULT_OPTIONS = [
  { value: 'ALL', label: 'All Fault Policies' },
  { value: 'latency', label: 'Latency & Chaos Matrix' },
  { value: '502', label: '502 Bad Gateway' },
  { value: '504', label: '504 Gateway Timeout' },
  { value: '429', label: '429 Rate Limit' },
  { value: 'TOKEN_MINTED', label: 'Token Minted' },
  { value: 'TOKEN_REVOKED', label: 'Token Revoked' },
];

function formatDateTime(iso: string): { time: string; date: string } {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return { time: '--:--', date: '----' };
  const pad = (n: number) => (n < 10 ? `0${n}` : String(n));
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  return { time, date };
}

function renderFaultBadges(log: LogItem) {
  const policy = log.faultPolicy;
  const fault = policy?.fault || log.injectedFault;

  if (fault === 'TOKEN_MINTED') {
    return <span className={styles.badgeGreen}>Token Minted</span>;
  }
  if (fault === 'TOKEN_REVOKED') {
    return <span className={styles.badgeNeutral}>Token Revoked</span>;
  }
  if (fault === '502') {
    return <span className={styles.badgeRed}>502 Bad Gateway</span>;
  }
  if (fault === '504') {
    return <span className={styles.badgeRed}>504 Gateway Timeout</span>;
  }
  if (fault === '429') {
    return <span className={styles.badgeAmber}>429 Rate Limit</span>;
  }
  if (fault === 'latency') {
    const lat = policy?.latency ?? log.latencyMs ?? 0;
    const jit = policy?.jitter ?? 0;
    const drop = policy?.packetLoss ?? 0;
    const dist = policy?.distribution;
    const mut = policy?.mutilationStrategy;

    return (
      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
        <span className={styles.badgeAmber}>Lat: {lat}ms</span>
        {jit > 0 && <span className={styles.badgeAmber}>Jit: ±{jit}ms</span>}
        {drop > 0 && <span className={styles.badgeRed}>Drop: {drop}%</span>}
        {dist && <span className={styles.badgeNeutral}>{dist}</span>}
        {mut && mut !== 'None' && <span className={styles.badgeRed}>{mut}</span>}
      </div>
    );
  }

  return <span className={styles.badgeNeutral}>{fault}</span>;
}

export default function AuditLogsPage() {
  const { data: session, status } = useSession();
  const isLoggedIn = status === 'authenticated' && !!session?.user;

  const [logs, setLogs] = useState<LogItem[]>([]);
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Filters
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [faultFilter, setFaultFilter] = useState('ALL');
  const [targetSearch, setTargetSearch] = useState('');

  const fetchLogs = useCallback(async (isManual = false) => {
    if (!isLoggedIn) return;
    if (isManual) setIsRefreshing(true);

    try {
      const params = new URLSearchParams({ limit: '50' });
      if (sourceFilter !== 'ALL') params.set('source', sourceFilter);
      if (faultFilter !== 'ALL') params.set('fault', faultFilter);
      if (targetSearch.trim()) params.set('target', targetSearch.trim());

      const res = await fetch(`/api/audit/logs?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        if (data.success) {
          setLogs(data.logs || []);
          setSummary(data.summary || null);
        }
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setIsLoading(false);
      if (isManual) setIsRefreshing(false);
    }
  }, [isLoggedIn, sourceFilter, faultFilter, targetSearch]);

  useEffect(() => {
    if (isLoggedIn) {
      fetchLogs();
    } else if (status !== 'loading') {
      setIsLoading(false);
    }
  }, [isLoggedIn, status, fetchLogs]);

  // Auto-refresh interval with Page Visibility API support
  useEffect(() => {
    if (!isLoggedIn || !autoRefresh) return;

    const interval = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      fetchLogs(false);
    }, 6000);

    const handleVisibility = () => {
      if (!document.hidden) {
        fetchLogs(false);
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [isLoggedIn, autoRefresh, fetchLogs]);

  if (status === 'loading' || (isLoading && isLoggedIn)) {
    return (
      <div className={styles.container}>
        <div style={{ padding: '80px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <Activity size={32} className="animate-spin" style={{ margin: '0 auto 16px', opacity: 0.6 }} />
          <p>Connecting to Cloudflare D1 distributed audit telemetry...</p>
        </div>
      </div>
    );
  }

  if (!isLoggedIn) {
    return (
      <div className={styles.container}>
        <div className={styles.headerSection}>
          <div className={styles.titleArea}>
            <h1>
              <Activity size={26} color="#10b981" />
              <span>Audit & Telemetry Logs</span>
            </h1>
            <p className={styles.subtitle}>Unified historical log trail for Web UI, Agent API, and Edge Ingress</p>
          </div>
        </div>

        <div style={{
          background: 'var(--dash-card-bg, rgba(255, 255, 255, 0.02))',
          border: '1px solid var(--dash-card-border, rgba(255, 255, 255, 0.08))',
          borderRadius: '16px',
          padding: '60px 24px',
          textAlign: 'center',
          maxWidth: '560px',
          margin: '40px auto'
        }}>
          <Shield size={48} color="#10b981" style={{ margin: '0 auto 20px', opacity: 0.8 }} />
          <h2 style={{ fontSize: '20px', fontWeight: 600, margin: '0 0 8px' }}>Sign in to View Audit Trail</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px', lineHeight: 1.6 }}>
            Every chaos token minted via Web or Agent API, as well as traffic hitting our Data Plane gateway, produces structured logs linked to your account.
          </p>
          <button
            className="btn-primary"
            style={{ padding: '10px 24px', fontSize: '14px', cursor: 'pointer' }}
            onClick={() => signIn('github', { callbackUrl: '/logs' })}
          >
            Sign in with GitHub
          </button>
        </div>
      </div>
    );
  }

  const topHost = summary?.topTargets?.[0]?.target || 'N/A';
  const topHostCount = summary?.topTargets?.[0]?.count || 0;

  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.headerSection}>
        <div className={styles.titleArea}>
          <h1>
            <Activity size={28} color="#10b981" />
            <span>Audit & Telemetry Logs</span>
            <span className={styles.liveTag}>
              <div className={styles.liveDot} />
              Live Ingress
            </span>
          </h1>
          <p className={styles.subtitle}>
            Real-time observability and audit trail across Web Console, AI Agents, and Gateway Ingress
          </p>
        </div>

        <div className={styles.headerActions}>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              style={{ accentColor: '#10b981' }}
            />
            Auto-refresh (6s)
          </label>
          <button className={styles.refreshBtn} onClick={() => fetchLogs(true)} disabled={isRefreshing}>
            <RefreshCw size={13} className={isRefreshing ? 'animate-spin' : ''} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className={styles.kpiGrid}>
        <div className={styles.kpiCard}>
          <div className={styles.kpiLabel}>Total Injections</div>
          <div className={styles.kpiValue}>{summary?.totalInjections ?? logs.length}</div>
          <div className={styles.kpiSub}>Lifetime recorded chaos events</div>
        </div>

        <div className={styles.kpiCard}>
          <div className={styles.kpiLabel}>Today's Invocations</div>
          <div className={styles.kpiValue} style={{ color: '#10b981' }}>
            {summary?.todayInjections ?? 0}
          </div>
          <div className={styles.kpiSub}>Events executed since UTC 00:00</div>
        </div>

        <div className={styles.kpiCard}>
          <div className={styles.kpiLabel}>Top Target Host</div>
          <div className={styles.kpiValue} style={{ fontSize: '20px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {topHost}
          </div>
          <div className={styles.kpiSub}>
            {topHostCount > 0 ? `${topHostCount} requests directed here` : 'No traffic recorded'}
          </div>
        </div>

        <div className={styles.kpiCard}>
          <div className={styles.kpiLabel}>Active Fault Breakdown</div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '4px' }}>
            {Object.entries(summary?.faultCounts || {}).slice(0, 4).map(([f, count]) => (
              <span key={f} className={styles.badgeNeutral} style={{ fontSize: '10px' }}>
                {f}: {count}
              </span>
            ))}
            {Object.keys(summary?.faultCounts || {}).length === 0 && (
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>None yet</span>
            )}
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className={styles.filterBar}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
          <Filter size={14} />
          <span style={{ fontSize: '12px', fontWeight: 600 }}>Filter:</span>
        </div>

        <div className={styles.filterSelectWrapper}>
          <CustomSelect
            options={SOURCE_OPTIONS}
            value={sourceFilter}
            onChange={(val) => setSourceFilter(val)}
          />
        </div>

        <div className={styles.filterSelectWrapper} style={{ minWidth: '200px' }}>
          <CustomSelect
            options={FAULT_OPTIONS}
            value={faultFilter}
            onChange={(val) => setFaultFilter(val)}
          />
        </div>

        <div className={styles.searchContainer}>
          <div className={styles.searchIconWrapper}>
            <Search size={14} />
          </div>
          <input
            type="text"
            className={styles.searchInput}
            placeholder="Search target host (e.g. example.com)..."
            value={targetSearch}
            onChange={(e) => setTargetSearch(e.target.value)}
          />
          {targetSearch && (
            <button
              onClick={() => setTargetSearch('')}
              className={styles.clearSearchBtn}
              title="Clear search"
            >
              <X size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Logs Table */}
      <div className={styles.tableCard}>
        <div className={styles.tableContainer}>
          {logs.length === 0 ? (
            <div className={styles.emptyState}>
              <Terminal size={36} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
              <h3>No matching audit logs found</h3>
              <p>Trigger a fault injection from the Dashboard or via Codex Skill to record telemetry events.</p>
            </div>
          ) : (
            <table className={styles.logsTable}>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Target Host</th>
                  <th>Injected Fault Policy</th>
                  <th>PoP</th>
                  <th>Token Hint</th>
                  <th>Ray ID</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => {
                  const dt = formatDateTime(log.executedAt);
                  const sourceClass =
                    log.source === 'AGENT_API'
                      ? styles.sourceAgent
                      : log.source === 'WEB_DASHBOARD'
                      ? styles.sourceWeb
                      : styles.sourceEdge;

                  let displayHost = log.targetUrl;
                  try {
                    if (displayHost.startsWith('http://') || displayHost.startsWith('https://')) {
                      displayHost = new URL(displayHost).hostname;
                    }
                  } catch {}

                  const isKnownColo =
                    log.edgeColo &&
                    log.edgeColo !== 'GLOBAL-EDGE' &&
                    log.edgeColo !== 'UNKNOWN' &&
                    log.edgeColo !== 'ANYCAST';

                  return (
                    <tr key={log.id}>
                      <td className={styles.timeCol}>
                        <span>{dt.time}</span> <span style={{ opacity: 0.5, fontSize: '10px' }}>{dt.date}</span>
                      </td>
                      <td>
                        <span className={`${styles.badgeSource} ${sourceClass}`}>
                          {log.source === 'AGENT_API' ? 'AI Agent' : log.source === 'WEB_DASHBOARD' ? 'Web UI' : 'Edge Ingress'}
                        </span>
                      </td>
                      <td className={styles.targetCol} title={log.targetUrl}>
                        {displayHost}
                      </td>
                      <td>
                        {renderFaultBadges(log)}
                      </td>
                      <td>
                        {isKnownColo ? (
                          <span className={styles.coloTagActive}>
                            <span className={styles.coloDot} />
                            {log.edgeColo}
                          </span>
                        ) : (
                          <span className={styles.coloTag}>{log.edgeColo || 'GLOBAL-EDGE'}</span>
                        )}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>
                        {log.tokenHint || '-'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#64748b' }}>
                        {log.rayId ? (log.rayId.includes('-') ? log.rayId.split('-')[0].slice(0, 10) + '...' : log.rayId.slice(0, 10) + '...') : '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
