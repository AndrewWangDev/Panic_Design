"use client";

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import { Key, Activity, BookOpen, Bug, LogOut, ShieldAlert, UserX, Terminal, Copy, Check } from 'lucide-react';
import { signOut } from 'next-auth/react';
import styles from './UserDropdown.module.css';

interface UserDropdownProps {
  user: {
    name: string;
    email: string;
    avatarUrl: string;
    tokens: number;
    usage: number;
  }
}

interface UserStatsData {
  tokens: number;
  dailyUsage: number;
  dailyLimit: number;
  hourlyUsage: number;
  hourlyLimit: number;
  nextHourReset: string;
  nextDayReset: string;
}

export default function UserDropdown({ user }: UserDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [stats, setStats] = useState({ 
    tokens: user.tokens, 
    dailyUsage: 0, 
    dailyLimit: 100,
    hourlyUsage: 0,
    hourlyLimit: 30,
    nextHourReset: '',
    nextDayReset: ''
  });
  const [isRevoking, setIsRevoking] = useState(false);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  
  // Developer API Key Modal states
  const [showApiKeyModal, setShowApiKeyModal] = useState(false);
  const [apiKeyInfo, setApiKeyInfo] = useState<{ hasKey: boolean; prefix: string | null; createdAt: string | null }>({
    hasKey: false,
    prefix: null,
    createdAt: null
  });
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);
  const [isKeyLoading, setIsKeyLoading] = useState(false);
  const [hasCopiedKey, setHasCopiedKey] = useState(false);

  const dropdownRef = useRef<HTMLDivElement>(null);

  const fetchApiKeyInfo = async () => {
    try {
      const res = await fetch('/api/user/api-key');
      if (res.ok) {
        const data = await res.json();
        setApiKeyInfo(data);
      }
    } catch (e) {
      console.error('Failed to fetch API key info:', e);
    }
  };

  const handleOpenApiKeyModal = () => {
    setIsOpen(false);
    setShowApiKeyModal(true);
    setNewlyCreatedKey(null);
    setHasCopiedKey(false);
    fetchApiKeyInfo();
  };

  const handleGenerateApiKey = async () => {
    setIsKeyLoading(true);
    try {
      const res = await fetch('/api/user/api-key', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setNewlyCreatedKey(data.apiKey);
        setApiKeyInfo({
          hasKey: true,
          prefix: data.prefix,
          createdAt: data.createdAt
        });
      } else {
        alert('Failed to generate API Key.');
      }
    } catch (e) {
      console.error(e);
      alert('Error generating API key.');
    }
    setIsKeyLoading(false);
  };

  const handleRevokeApiKey = async () => {
    if (!confirm('Are you sure you want to revoke this Developer API Key? Any AI Agents or scripts using this key will immediately be blocked.')) {
      return;
    }
    setIsKeyLoading(true);
    try {
      const res = await fetch('/api/user/api-key', { method: 'DELETE' });
      if (res.ok) {
        setApiKeyInfo({ hasKey: false, prefix: null, createdAt: null });
        setNewlyCreatedKey(null);
      } else {
        alert('Failed to revoke API Key.');
      }
    } catch (e) {
      console.error(e);
      alert('Error revoking API key.');
    }
    setIsKeyLoading(false);
  };

  const handleCopyKey = () => {
    if (!newlyCreatedKey) return;
    navigator.clipboard.writeText(newlyCreatedKey);
    setHasCopiedKey(true);
    setTimeout(() => setHasCopiedKey(false), 2000);
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/user/stats')
        .then(res => res.ok ? (res.json() as Promise<UserStatsData>) : null)
        .then((data: UserStatsData | null) => {
          if (data) setStats({ 
            tokens: data.tokens, 
            dailyUsage: data.dailyUsage, 
            dailyLimit: data.dailyLimit,
            hourlyUsage: data.hourlyUsage,
            hourlyLimit: data.hourlyLimit,
            nextHourReset: data.nextHourReset,
            nextDayReset: data.nextDayReset
          });
        })
        .catch(console.error);
    }
  }, [isOpen]);

  const handleRevokeAllClick = () => {
    setShowRevokeModal(true);
    setIsOpen(false);
  };

  const executeRevokeAll = async () => {
    setIsRevoking(true);
    try {
      const res = await fetch('/api/user/revoke-all', { method: 'POST' });
      if (res.ok) {
        setStats(s => ({ ...s, tokens: 0 }));
        if (window.location.pathname === '/dashboard') {
          window.location.reload();
        }
      } else {
        alert('Failed to revoke tokens.');
      }
    } catch (e) {
      console.error(e);
      alert('Error revoking tokens.');
    }
    setIsRevoking(false);
    setShowRevokeModal(false);
  };

  const handleDeleteClick = () => {
    setShowDeleteModal(true);
    setIsOpen(false);
  };

  const executeDeleteAccount = async () => {
    setIsDeleting(true);
    try {
      const res = await fetch('/api/user/delete', { method: 'POST' });
      if (res.ok) {
        // Force a hard navigation to clear Next.js App Router cache
        window.location.href = '/';
      } else {
        alert('Failed to delete account.');
      }
    } catch (e) {
      console.error(e);
      alert('Error deleting account.');
    }
    setIsDeleting(false);
    setShowDeleteModal(false);
  };

  const hourlyPercent = Math.min((stats.hourlyUsage / Math.max(stats.hourlyLimit, 1)) * 100, 100);
  const dailyPercent = Math.min((stats.dailyUsage / Math.max(stats.dailyLimit, 1)) * 100, 100);

  return (
    <div className={styles.dropdownContainer} ref={dropdownRef}>
      <button 
        className={styles.avatarBtn} 
        onClick={() => setIsOpen(!isOpen)}
        aria-label="User Menu"
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={user.avatarUrl} alt="Avatar" className={styles.avatarImg} />
      </button>

      {isOpen && (
        <div className={styles.dropdownMenu}>
          {/* Area 1: The Identity Block */}
          <div className={styles.identityBlock}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={user.avatarUrl} alt="Avatar" className={styles.identityAvatar} />
            <div className={styles.identityInfo}>
              <div className={styles.username}>{user.name}</div>
              <div className={styles.email}>{user.email}</div>
            </div>
          </div>

          <div className={styles.divider} />

          {/* Area 2: Assets & Usage */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <div className={styles.sectionTitle}>
                <Key size={14} /> Edge Tokens
              </div>
              <span className={styles.badge}>{stats.tokens} active</span>
            </div>
            <button 
              className={styles.revokeBtn} 
              onClick={handleRevokeAllClick}
              disabled={isRevoking}
            >
              <ShieldAlert size={14} /> {isRevoking ? 'Revoking...' : 'Revoke All'}
            </button>
          </div>

          {/* Developer API Key Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <div className={styles.sectionTitle}>
                <Terminal size={14} /> Developer API Key
              </div>
              <span className={styles.badge} style={{ background: apiKeyInfo.hasKey ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.05)', color: apiKeyInfo.hasKey ? '#10b981' : '#94a3b8' }}>
                {apiKeyInfo.hasKey ? 'Active' : 'None'}
              </span>
            </div>
            <button 
              className={styles.revokeBtn} 
              style={{ borderColor: 'rgba(255, 255, 255, 0.1)', color: '#94a3b8' }}
              onClick={handleOpenApiKeyModal}
            >
              <Key size={14} /> Manage API Key
            </button>
          </div>

          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <div className={styles.sectionTitle}>
                <Activity size={14} /> Hourly Quota
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <span className={styles.usageText}>{stats.hourlyUsage} / {stats.hourlyLimit}</span>
                {stats.nextHourReset && <span style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>Resets at {new Date(stats.nextHourReset).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>}
              </div>
            </div>
            <div className={styles.progressBarBg}>
              <div 
                className={styles.progressBarFill} 
                style={{ width: `${hourlyPercent}%` }} 
              />
            </div>
          </div>

          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <div className={styles.sectionTitle}>
                <Activity size={14} /> Daily Quota
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <span className={styles.usageText}>{stats.dailyUsage} / {stats.dailyLimit}</span>
                {stats.nextDayReset && <span style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>Resets at {new Date(stats.nextDayReset).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>}
              </div>
            </div>
            <div className={styles.progressBarBg}>
              <div 
                className={styles.progressBarFill} 
                style={{ width: `${dailyPercent}%` }} 
              />
            </div>
          </div>

          <div className={styles.divider} />

          {/* Area 3: Docs & Support */}
          <div className={styles.menuList}>
            <Link href="/logs" className={styles.menuItem} onClick={() => setIsOpen(false)}>
              <Activity size={16} /> Audit Logs
            </Link>
            <Link href="/docs" className={styles.menuItem} onClick={() => setIsOpen(false)}>
              <BookOpen size={16} /> API Documentation
            </Link>
            <a href="https://github.com/AndrewWangDev/panic_design/issues" target="_blank" rel="noreferrer" className={styles.menuItem}>
              <Bug size={16} /> Report an Issue
            </a>
          </div>

          <div className={styles.divider} />

          {/* Area 4: Logout */}
          <div className={styles.menuList}>
            <button className={styles.menuItemLogOut} onClick={() => { setIsLoggingOut(true); signOut(); }} disabled={isLoggingOut}>
              <LogOut size={16} /> {isLoggingOut ? 'Logging out...' : 'Log out'}
            </button>
            <button className={styles.menuItemDelete} onClick={handleDeleteClick}>
              <UserX size={16} /> Delete Account
            </button>
          </div>
        </div>
      )}

      {/* Revoke Modal */}
      {showRevokeModal && (
        <div className={styles.modalOverlay}>
          <div className={styles.modalContent}>
            <div className={styles.modalHeader}>
              <ShieldAlert size={24} className={styles.modalIcon} />
              <div className={styles.modalTitle}>Revoke All Tokens</div>
            </div>
            <div className={styles.modalBody}>
              Are you sure you want to revoke <strong>ALL</strong> your edge tokens? This will instantly block all traffic using these tokens and cannot be undone.
            </div>
            <div className={styles.modalActions}>
              <button className={styles.cancelBtn} onClick={() => setShowRevokeModal(false)} disabled={isRevoking}>
                Cancel
              </button>
              <button className={styles.confirmRevokeBtn} onClick={executeRevokeAll} disabled={isRevoking}>
                {isRevoking ? 'Revoking...' : 'Yes, Revoke All'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Account Modal */}
      {showDeleteModal && (
        <div className={styles.modalOverlay}>
          <div className={styles.modalContent}>
            <div className={styles.modalHeader}>
              <UserX size={24} className={styles.modalIconDelete} />
              <div className={styles.modalTitleDelete}>Delete Account</div>
            </div>
            <div className={styles.modalBody}>
              Are you sure you want to delete your account? This will <strong>permanently disconnect</strong> your GitHub profile, scramble your identity, and instantly revoke all active chaos tokens.<br /><br />
              Your historical metrics will be kept anonymously for system integrity, but you will permanently lose access to your remaining usage quota.
            </div>
            <div className={styles.modalActions}>
              <button className={styles.cancelBtn} onClick={() => setShowDeleteModal(false)} disabled={isDeleting}>
                Cancel
              </button>
              <button className={styles.confirmDeleteBtn} onClick={executeDeleteAccount} disabled={isDeleting}>
                {isDeleting ? 'Deleting...' : 'Delete My Account'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Developer API Key Modal */}
      {showApiKeyModal && (
        <div className={styles.modalOverlay}>
          <div className={styles.modalContent} style={{ maxWidth: '460px' }}>
            <div className={styles.modalHeader}>
              <Terminal size={24} className={styles.modalIcon} style={{ color: '#10b981' }} />
              <div className={styles.modalTitle}>Developer API Key</div>
            </div>
            <div className={styles.modalBody} style={{ fontSize: '13px', lineHeight: '1.6' }}>
              Used by <strong>AI Agents (Codex / Muse / Cursor)</strong> to mint and revoke chaos tokens via <code>SKILL.md</code> without using the Web UI.
              
              {newlyCreatedKey ? (
                <div style={{ marginTop: '16px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '12px' }}>
                  <div style={{ color: '#10b981', fontWeight: 600, fontSize: '12px', marginBottom: '8px' }}>
                    ⚠️ Copy this key now! It will never be shown again:
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(0,0,0,0.5)', padding: '8px 10px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '11px', color: '#fff', wordBreak: 'break-all' }}>
                    <span style={{ flex: 1 }}>{newlyCreatedKey}</span>
                    <button
                      onClick={handleCopyKey}
                      style={{ background: '#10b981', border: 'none', borderRadius: '4px', padding: '5px 10px', color: '#000', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      {hasCopiedKey ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
                    </button>
                  </div>
                </div>
              ) : apiKeyInfo.hasKey ? (
                <div style={{ marginTop: '16px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '12px' }}>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Current Active Key Prefix:</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#10b981', marginTop: '4px' }}>
                    {apiKeyInfo.prefix}
                  </div>
                  {apiKeyInfo.createdAt && (
                    <div style={{ fontSize: '11px', color: '#666', marginTop: '4px' }}>
                      Created: {new Date(apiKeyInfo.createdAt).toLocaleString()}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ marginTop: '14px', color: '#94a3b8' }}>
                  You do not have an active API Key yet. Generating one allows Codex or CLI scripts to automate chaos engineering tests.
                </div>
              )}
            </div>
            <div className={styles.modalActions} style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
              <div>
                {apiKeyInfo.hasKey && !newlyCreatedKey && (
                  <button
                    className={styles.cancelBtn}
                    style={{ color: '#f87171', borderColor: 'rgba(248, 113, 113, 0.2)' }}
                    onClick={handleRevokeApiKey}
                    disabled={isKeyLoading}
                  >
                    Revoke Key
                  </button>
                )}
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className={styles.cancelBtn} onClick={() => setShowApiKeyModal(false)}>
                  Close
                </button>
                <button
                  className={styles.confirmRevokeBtn}
                  style={{ background: '#10b981', color: '#000' }}
                  onClick={handleGenerateApiKey}
                  disabled={isKeyLoading}
                >
                  {isKeyLoading ? 'Generating...' : apiKeyInfo.hasKey ? 'Rotate Key' : 'Generate Key'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
