"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  X,
  Copy,
  Check,
  Bot,
  Terminal,
  Cpu,
  FileCode,
  ArrowRight,
  Sparkles,
  ShieldAlert,
  Download
} from 'lucide-react';
import styles from './AgentSkillModal.module.css';

interface AgentSkillModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type TabType = 'cursor' | 'claude' | 'antigravity' | 'raw';

export default function AgentSkillModal({ isOpen, onClose }: AgentSkillModalProps) {
  const [activeTab, setActiveTab] = useState<TabType>('cursor');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey(null);
    }, 2000);
  };

  const cursorCmd = `mkdir -p .cursor/rules && curl -sSL https://panic.andrewwangdev.com/SKILL.md -o .cursor/rules/panic-chaos.mdc`;
  const claudeCmd = `mkdir -p skills/panic-chaos && curl -sSL https://panic.andrewwangdev.com/SKILL.md -o skills/panic-chaos/SKILL.md`;
  const antigravityCmd = `mkdir -p ~/.gemini/antigravity/skills/panic-chaos && curl -sSL https://panic.andrewwangdev.com/SKILL.md -o ~/.gemini/antigravity/skills/panic-chaos/SKILL.md`;
  const envCmd = `export PANIC_DESIGN_API_KEY="pd_live_..."`;
  const rawUrl = `https://panic.andrewwangdev.com/SKILL.md`;

  return (
    <div className={styles.overlay} onClick={onClose} role="dialog" aria-modal="true">
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.headerGlow} />
          <div className={styles.titleArea}>
            <div className={styles.badge}>
              <Sparkles size={12} />
              <span>M2M Agent Skills</span>
            </div>
            <h2 className={styles.title}>Connect Panic Design to AI Agents</h2>
            <p className={styles.subtitle}>
              Equip Cursor, Claude Code, Codex, or Antigravity with edge chaos injection superpowers.
            </p>
          </div>
          <button className={styles.closeBtn} onClick={onClose} aria-label="Close modal">
            <X size={18} />
          </button>
        </div>

        {/* Ecosystem Tabs */}
        <div className={styles.tabs}>
          <button
            className={`${styles.tab} ${activeTab === 'cursor' ? styles.activeTab : ''}`}
            onClick={() => setActiveTab('cursor')}
          >
            <Bot size={15} />
            <span>Cursor</span>
          </button>
          <button
            className={`${styles.tab} ${activeTab === 'claude' ? styles.activeTab : ''}`}
            onClick={() => setActiveTab('claude')}
          >
            <Terminal size={15} />
            <span>Claude Code / Codex</span>
          </button>
          <button
            className={`${styles.tab} ${activeTab === 'antigravity' ? styles.activeTab : ''}`}
            onClick={() => setActiveTab('antigravity')}
          >
            <Cpu size={15} />
            <span>Antigravity</span>
          </button>
          <button
            className={`${styles.tab} ${activeTab === 'raw' ? styles.activeTab : ''}`}
            onClick={() => setActiveTab('raw')}
          >
            <FileCode size={15} />
            <span>Raw SKILL.md</span>
          </button>
        </div>

        {/* Tab Body */}
        <div className={styles.body}>
          {activeTab === 'cursor' && (
            <>
              <p className={styles.tabDesc}>
                Install into your workspace as a Cursor Rule. Cursor Composer & Chat will autonomously invoke the Chaos API to stress-test your client retry policies, timeouts, and fallback logic.
              </p>

              <div className={styles.codeSection}>
                <div className={styles.codeLabel}>
                  <span>1. Install Workspace Rule (Run in Terminal)</span>
                </div>
                <div className={styles.codeBox}>
                  <div className={styles.codeText}>{cursorCmd}</div>
                  <button
                    className={`${styles.copyBtn} ${copiedKey === 'cursor-cmd' ? styles.copiedBtn : ''}`}
                    onClick={() => copyToClipboard(cursorCmd, 'cursor-cmd')}
                  >
                    {copiedKey === 'cursor-cmd' ? (
                      <>
                        <Check size={13} /> Copied!
                      </>
                    ) : (
                      <>
                        <Copy size={13} /> Copy
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className={styles.tipBox}>
                <strong>💡 Quick Prompt Example:</strong>
                <div style={{ marginTop: '4px', fontStyle: 'italic', color: '#e4e4e7' }}>
                  &ldquo;@panic-chaos Inject a 502 Bad Gateway to our mock payment endpoint and verify the circuit breaker opens as expected.&rdquo;
                </div>
              </div>
            </>
          )}

          {activeTab === 'claude' && (
            <>
              <p className={styles.tabDesc}>
                Add to your project’s <code>skills/</code> folder. Claude Code or OpenAI Codex can autonomously mint ephemeral edge tokens and run full fault-injection evaluation suites.
              </p>

              <div className={styles.codeSection}>
                <div className={styles.codeLabel}>
                  <span>1. Install Skill File</span>
                </div>
                <div className={styles.codeBox}>
                  <div className={styles.codeText}>{claudeCmd}</div>
                  <button
                    className={`${styles.copyBtn} ${copiedKey === 'claude-cmd' ? styles.copiedBtn : ''}`}
                    onClick={() => copyToClipboard(claudeCmd, 'claude-cmd')}
                  >
                    {copiedKey === 'claude-cmd' ? (
                      <>
                        <Check size={13} /> Copied!
                      </>
                    ) : (
                      <>
                        <Copy size={13} /> Copy
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className={styles.codeSection}>
                <div className={styles.codeLabel}>
                  <span>2. Provide Developer API Key</span>
                </div>
                <div className={styles.codeBox}>
                  <div className={styles.codeText}>{envCmd}</div>
                  <button
                    className={`${styles.copyBtn} ${copiedKey === 'claude-env' ? styles.copiedBtn : ''}`}
                    onClick={() => copyToClipboard(envCmd, 'claude-env')}
                  >
                    {copiedKey === 'claude-env' ? (
                      <>
                        <Check size={13} /> Copied!
                      </>
                    ) : (
                      <>
                        <Copy size={13} /> Copy
                      </>
                    )}
                  </button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'antigravity' && (
            <>
              <p className={styles.tabDesc}>
                Load directly into Google Antigravity or native Multi-Agent Swarms for autonomous chaos orchestration during multi-agent test sprints.
              </p>

              <div className={styles.codeSection}>
                <div className={styles.codeLabel}>
                  <span>Install to Antigravity Global Skills</span>
                </div>
                <div className={styles.codeBox}>
                  <div className={styles.codeText}>{antigravityCmd}</div>
                  <button
                    className={`${styles.copyBtn} ${copiedKey === 'antigravity-cmd' ? styles.copiedBtn : ''}`}
                    onClick={() => copyToClipboard(antigravityCmd, 'antigravity-cmd')}
                  >
                    {copiedKey === 'antigravity-cmd' ? (
                      <>
                        <Check size={13} /> Copied!
                      </>
                    ) : (
                      <>
                        <Copy size={13} /> Copy
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className={styles.tipBox}>
                <strong>🤖 Swarm Ready:</strong> Use alongside subagents to inject unpredictable 444 resets, payload corruptions, and 1200ms latency spikes during automated verification.
              </div>
            </>
          )}

          {activeTab === 'raw' && (
            <>
              <p className={styles.tabDesc}>
                Reference or download the raw, OpenAPI-compliant <code>SKILL.md</code> specification directly for custom LLM prompts, MCP servers, or CI/CD pipelines.
              </p>

              <div className={styles.codeSection}>
                <div className={styles.codeLabel}>
                  <span>Public Skill URL</span>
                </div>
                <div className={styles.codeBox}>
                  <div className={styles.codeText}>{rawUrl}</div>
                  <button
                    className={`${styles.copyBtn} ${copiedKey === 'raw-url' ? styles.copiedBtn : ''}`}
                    onClick={() => copyToClipboard(rawUrl, 'raw-url')}
                  >
                    {copiedKey === 'raw-url' ? (
                      <>
                        <Check size={13} /> Copied!
                      </>
                    ) : (
                      <>
                        <Copy size={13} /> Copy
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <a
                  href="/SKILL.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.copyBtn}
                  style={{ padding: '8px 16px', textDecoration: 'none' }}
                >
                  <FileCode size={14} /> Open in Browser
                </a>
                <a
                  href="/SKILL.md"
                  download="panic-design-chaos-SKILL.md"
                  className={styles.copyBtn}
                  style={{ padding: '8px 16px', textDecoration: 'none' }}
                >
                  <Download size={14} /> Download File
                </a>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className={styles.footer}>
          <div className={styles.footerNote}>
            <span>🔑 Requires Developer API Key (<code>pd_live_...</code>) from User Menu.</span>
          </div>
          <Link href="/docs#agent-integration" className={styles.docsLink} onClick={onClose}>
            <span>View Full M2M Spec</span>
            <ArrowRight size={13} />
          </Link>
        </div>
      </div>
    </div>
  );
}
