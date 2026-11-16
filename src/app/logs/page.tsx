"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { useSession, signIn } from 'next-auth/react';
import { Activity, RefreshCw, Filter, Search, Terminal, Globe, Shield, ArrowUpRight } from 'lucide-react';
import styles from './logs.module.css';

interface LogItem {
  id: string;
  source: string;
  targetUrl: string;
  injectedFault: string;
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

  // Auto-refresh interval
  useEffect(() => {
    if (!isLoggedIn || !autoRefresh) return;
    const interval = setInterval(() => {
      fetchLogs(false);
    }, 6000);
    return () => clearInterval(interval);
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
              <span key={f} className={styles.badgeFault} style={{ fontSize: '10px' }}>
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

        <select
          className={styles.selectInput}
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
        >
          <option value="ALL">All Sources</option>
          <option value="WEB_DASHBOARD">Web Dashboard</option>
          <option value="AGENT_API">AI Agent (Codex/API)</option>
          <option value="DIRECT_DATA_PLANE">Direct Gateway</option>
        </select>

        <select
          className={styles.selectInput}
          value={faultFilter}
          onChange={(e) => setFaultFilter(e.target.value)}
        >
          <option value="ALL">All Faults</option>
          <option value="502">502 Bad Gateway</option>
          <option value="504">504 Gateway Timeout</option>
          <option value="429">429 Rate Limit</option>
          <option value="latency">Latency & Packet Loss</option>
          <option value="TOKEN_MINTED">Token Minted</option>
          <option value="TOKEN_REVOKED">Token Revoked</option>
        </select>

        <div style={{ position: 'relative', flex: 1, minWidth: '180px' }}>
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
              style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: '#888', cursor: 'pointer' }}
            >
              ×
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
                  <th>Injected Fault</th>
                  <th>PoP</th>
                  <th>Token Hint</th>
                  <th>Ray ID</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => {
                  const date = new Date(log.executedAt);
                  const sourceClass =
                    log.source === 'AGENT_API'
                      ? styles.sourceAgent
                      : log.source === 'WEB_DASHBOARD'
                      ? styles.sourceWeb
                      : styles.sourceEdge;

                  let faultClass = styles.faultLatency;
                  if (log.injectedFault === '502' || log.injectedFault === '504') {
                    faultClass = styles.fault502;
                  } else if (log.injectedFault === '429') {
                    faultClass = styles.fault429;
                  } else if (log.injectedFault === 'TOKEN_MINTED') {
                    faultClass = styles.faultMint;
                  }

                  let displayHost = log.targetUrl;
                  try {
                    if (displayHost.startsWith('http://') || displayHost.startsWith('https://')) {
                      displayHost = new URL(displayHost).hostname;
                    }
                  } catch {}

                  return (
                    <tr key={log.id}>
                      <td className={styles.timeCol}>
                        {date.toLocaleTimeString()} <span style={{ opacity: 0.5, fontSize: '10px' }}>{date.toLocaleDateString()}</span>
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
                        <span className={`${styles.badgeFault} ${faultClass}`}>
                          {log.injectedFault === 'TOKEN_MINTED' ? 'Token Minted' : log.injectedFault === 'TOKEN_REVOKED' ? 'Token Revoked' : log.injectedFault}
                          {log.latencyMs ? ` (+${log.latencyMs}ms)` : ''}
                        </span>
                      </td>
                      <td>
                        <span className={styles.coloTag}>{log.edgeColo || 'ANYCAST'}</span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>
                        {log.tokenHint || '-'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#64748b' }}>
                        {log.rayId ? log.rayId.slice(0, 12) + '...' : '-'}
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
