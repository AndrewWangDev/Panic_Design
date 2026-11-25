import { NextResponse } from 'next/server';
import type { PrismaClient } from '@prisma/client';

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): {
    first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  };
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}

export const ACTIVE_TOKEN_CAP = 5;
export const ACTIVE_TOKEN_WINDOW_DAYS = 7;

/**
 * Enforces strict separation between web authentication (AUTH_SECRET) and
 * chaos token signing/verification (CHAOS_JWT_SECRET) across all environments.
 */
export function requireChaosJwtSecret(env: unknown): string | null {
  const secret = (env as { CHAOS_JWT_SECRET?: string } | undefined)?.CHAOS_JWT_SECRET
    || process.env.CHAOS_JWT_SECRET;
  return typeof secret === 'string' && secret.length > 0 ? secret : null;
}

/**
 * Standard 500 Fail-Closed response when CHAOS_JWT_SECRET is missing.
 */
export function missingChaosJwtSecretResponse(): NextResponse {
  console.error('[SECURITY FATAL] Dedicated CHAOS_JWT_SECRET is missing. Request rejected (Fail-Closed SEC-03-EXT).');
  return NextResponse.json(
    { error: 'Server misconfiguration: CHAOS_JWT_SECRET is required' },
    { status: 500 }
  );
}

/**
 * Resolves effective TTL hours from serialized Token config JSON with safe fallback.
 */
export function resolveTokenTtlHours(configJson: string): number {
  try {
    const conf = JSON.parse(configJson);
    return conf.ttlHours || conf.ttl || 0.25;
  } catch {
    return 0.25;
  }
}

export interface ActiveTokenSummary {
  id: string;
  hint: string | null;
}

/**
 * Counts currently unexpired, unrevoked tokens for a user within the bounded active window.
 */
export async function countActiveTokens(
  prisma: PrismaClient,
  userId: string,
  nowMs: number = Date.now()
): Promise<{ activeCount: number; activeTokens: ActiveTokenSummary[]; windowStart: Date }> {
  const windowStart = new Date(nowMs - ACTIVE_TOKEN_WINDOW_DAYS * 24 * 60 * 60 * 1000);
  const unrevoked = await prisma.token.findMany({
    where: {
      userId,
      isRevoked: false,
      createdAt: { gte: windowStart }
    },
    select: {
      id: true,
      tokenHint: true,
      createdAt: true,
      config: true
    }
  });

  const activeTokens: ActiveTokenSummary[] = [];
  for (const t of unrevoked) {
    const ttlHours = resolveTokenTtlHours(t.config);
    const expiresAtMs = new Date(t.createdAt).getTime() + ttlHours * 3600 * 1000;
    if (expiresAtMs > nowMs) {
      activeTokens.push({ id: t.id, hint: t.tokenHint ?? null });
    }
  }

  return { activeCount: activeTokens.length, activeTokens, windowStart };
}

/**
 * Atomic single-statement D1 SQL enforcing concurrent active token cap (<= cap)
 * using D1 server clock (`strftime`/`unixepoch`) to eliminate cross-PoP clock skew
 * and multi-step TOCTOU windows.
 */
const ATOMIC_MINT_SQL = `
INSERT INTO "Token" (
  "id",
  "userId",
  "targetHost",
  "config",
  "tokenHint",
  "issuedWithSalt",
  "isRevoked",
  "createdAt"
)
SELECT ?, ?, ?, ?, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
WHERE (
  SELECT COUNT(*)
  FROM "Token"
  WHERE "userId" = ?
    AND "isRevoked" = 0
    AND "createdAt" >= strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now', '-8 days')
    AND (
      (CASE
        WHEN typeof("createdAt") IN ('integer', 'real') THEN ("createdAt" / 1000.0)
        ELSE COALESCE(unixepoch("createdAt", 'subsec'), 0)
      END)
      +
      (CASE
        WHEN json_valid("config") THEN COALESCE(
          NULLIF(CAST(json_extract("config", '$.ttlHours') AS REAL), 0),
          NULLIF(CAST(json_extract("config", '$.ttl') AS REAL), 0),
          0.25
        )
        ELSE 0.25
      END) * 3600.0
    ) > unixepoch('now', 'subsec')
) < ?
RETURNING "id", "createdAt"
`.trim();

export interface MintTokenParams {
  d1?: D1DatabaseLike | null;
  prisma: PrismaClient;
  userId: string;
  targetHost: string;
  config: string;
  issuedWithSalt: number;
  maxActiveWindowStart: Date;
  signJwt: (tokenId: string) => Promise<string>;
  cap?: number;
}

export interface PersistedTokenRecord {
  id: string;
  userId: string;
  targetHost: string;
  config: string;
  tokenHint: string;
  isRevoked: boolean;
  issuedWithSalt: number;
  createdAt: Date | string;
}

export type MintTokenResult =
  | { created: true; jwt: string; tokenHint: string; token: PersistedTokenRecord }
  | { created: false };

/**
 * Atomically mints and persists a Chaos Token only if the user's active tokens are strictly below `cap`.
 * Uses single-statement SQLite `INSERT ... SELECT ... WHERE COUNT < cap RETURNING` on D1 in production,
 * and falls back to Prisma mock coordination only in non-production test environments without D1 bindings.
 */
export async function mintTokenWithCap(params: MintTokenParams): Promise<MintTokenResult> {
  const {
    d1,
    prisma,
    userId,
    targetHost,
    config,
    issuedWithSalt,
    maxActiveWindowStart,
    signJwt,
    cap = ACTIVE_TOKEN_CAP
  } = params;

  // Primary atomic D1 path (single serialized SQLite write transaction)
  if (d1 && typeof d1.prepare === 'function') {
    const candidateId = crypto.randomUUID();
    const jwt = await signJwt(candidateId);
    const tokenHint = `eyJhbGci...${jwt.slice(-4)}`;

    const inserted = await d1
      .prepare(ATOMIC_MINT_SQL)
      .bind(
        candidateId,
        userId,
        targetHost,
        config,
        tokenHint,
        issuedWithSalt,
        userId,
        cap
      )
      .first<{ id: string; createdAt: string }>();

    if (!inserted) {
      return { created: false };
    }

    return {
      created: true,
      jwt,
      tokenHint,
      token: {
        id: inserted.id,
        userId,
        targetHost,
        config,
        tokenHint,
        isRevoked: false,
        issuedWithSalt,
        createdAt: new Date(inserted.createdAt)
      }
    };
  }

  // Fail closed in production if D1 binding is unexpectedly absent
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Cloudflare D1 binding (env.DB) is required for atomic token minting in production.');
  }

  // Unit-test-only fallback when Prisma is mocked without env.DB
  const token = await prisma.token.create({
    data: {
      userId,
      targetHost,
      config,
      tokenHint: '',
      issuedWithSalt,
      isRevoked: false
    }
  });

  const jwt = await signJwt(token.id);
  const tokenHint = `eyJhbGci...${jwt.slice(-4)}`;
  await prisma.token.update({
    where: { id: token.id },
    data: { tokenHint }
  });

  const postCheckTokens = await prisma.token.findMany({
    where: {
      userId,
      isRevoked: false,
      createdAt: { gte: maxActiveWindowStart }
    },
    select: {
      id: true,
      tokenHint: true,
      createdAt: true,
      config: true
    },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }]
  });

  const postNowMs = Date.now();
  const activeTokens: Array<{ id: string; isConfirmed: boolean; createdAtMs: number }> = [];
  for (const t of postCheckTokens) {
    const ttlH = resolveTokenTtlHours(t.config);
    const expMs = new Date(t.createdAt).getTime() + ttlH * 3600 * 1000;
    if (expMs > postNowMs) {
      activeTokens.push({
        id: t.id,
        isConfirmed: Boolean(t.tokenHint && t.tokenHint !== ''),
        createdAtMs: new Date(t.createdAt).getTime()
      });
    }
  }

  if (activeTokens.length > cap) {
    activeTokens.sort((a, b) => {
      if (a.isConfirmed !== b.isConfirmed) return a.isConfirmed ? -1 : 1;
      if (a.createdAtMs !== b.createdAtMs) return a.createdAtMs - b.createdAtMs;
      return a.id.localeCompare(b.id);
    });

    const allowedSlotIds = new Set(activeTokens.slice(0, cap).map(t => t.id));
    if (!allowedSlotIds.has(token.id)) {
      await prisma.token.update({
        where: { id: token.id },
        data: { isRevoked: true }
      }).catch(() => {});
      return { created: false };
    }
  }

  return {
    created: true,
    jwt,
    tokenHint,
    token: {
      ...token,
      tokenHint
    }
  };
}
