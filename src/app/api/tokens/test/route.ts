import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { isPrivateIp, resolveHostIps } from '@/lib/security';
import { jwtVerify } from 'jose';
import { getCloudflareContext } from '@opennextjs/cloudflare';

async function resolveHostIp(rawHost: string): Promise<string | null> {
  const { ips, primaryIp } = await resolveHostIps(rawHost);
  const blockedIp = ips.find((ip) => isPrivateIp(ip));
  if (blockedIp) {
    return blockedIp;
  }
  return primaryIp;
}

export async function POST(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { token } = await req.json() as any;
    if (!token || typeof token !== 'string') {
      return NextResponse.json({ error: 'Missing token' }, { status: 400 });
    }

    // Cryptographic JWT verification using CHAOS_JWT_SECRET or AUTH_SECRET
    const { env } = getCloudflareContext();
    const authSecret = (env as any)?.CHAOS_JWT_SECRET || (env as any)?.AUTH_SECRET || process.env.CHAOS_JWT_SECRET || process.env.AUTH_SECRET;
    if (!authSecret) {
      return NextResponse.json({ error: 'Server misconfiguration: missing signing secret' }, { status: 500 });
    }

    let payload: any;
    try {
      const secret = new TextEncoder().encode(authSecret);
      const verified = await jwtVerify(token, secret, { algorithms: ['HS256'] });
      payload = verified.payload;
    } catch {
      return NextResponse.json({
        error: 'INVALID_TOKEN',
        message: 'Chaos Token signature is invalid or expired.'
      }, { status: 400 });
    }

    // Verify token ownership
    if (payload.userId !== session.user.id) {
      return NextResponse.json({
        error: 'FORBIDDEN',
        message: 'Token does not belong to current authenticated session.'
      }, { status: 403 });
    }

    // Check rate limiting quota
    const { checkAndUpdateQuota } = await import('@/lib/quota');
    const quota = await checkAndUpdateQuota(session.user.id);
    if (!quota.allowed) {
      return NextResponse.json({ error: 'QUOTA_EXCEEDED', message: quota.reason }, { status: 429 });
    }

    const baseUrl = (env as any)?.DATA_PLANE_URL || process.env.DATA_PLANE_URL || 'https://gateway.andrewwangdev.com';
    const gatewayUrl = `${baseUrl.replace(/\/$/, '')}/?token=${encodeURIComponent(token)}`;
    
    const startTime = Date.now();
    let status = 0;
    let statusText = '';
    let responseBody = '';
    let resHeaders: Headers = new Headers();
    
    try {
      const res = await fetch(gatewayUrl, {
        method: 'GET',
        headers: {
          'Accept': '*/*'
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(10000)
      });
      status = res.status;
      statusText = res.statusText;
      resHeaders = res.headers;

      // Stream read up to 64KB to prevent Worker OOM on large upstream responses (ISSUE-04)
      const MAX_PREVIEW_BYTES = 64 * 1024;
      if (res.body) {
        const reader = res.body.getReader();
        const chunks: Uint8Array[] = [];
        let totalBytes = 0;
        let isTruncated = false;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            if (totalBytes + value.length > MAX_PREVIEW_BYTES) {
              const remaining = MAX_PREVIEW_BYTES - totalBytes;
              if (remaining > 0) chunks.push(value.slice(0, remaining));
              totalBytes += remaining;
              isTruncated = true;
              await reader.cancel();
              break;
            }
            chunks.push(value);
            totalBytes += value.length;
          }
        }

        const decoder = new TextDecoder('utf-8');
        const fullBuffer = new Uint8Array(totalBytes);
        let offset = 0;
        for (const chunk of chunks) {
          fullBuffer.set(chunk, offset);
          offset += chunk.length;
        }
        responseBody = decoder.decode(fullBuffer);
        if (isTruncated) {
          responseBody += '\n... [Response body truncated: exceeded 64KB preview limit]';
        }
      } else {
        responseBody = '';
      }
    } catch (e: any) {
      console.error('Data Plane probe failed:', e);
      status = 503;
      statusText = 'Service Unavailable (Data Plane offline)';
      responseBody = 'Upstream data plane unreachable or timed out.';
    }
    
    const t1_total = Date.now() - startTime;

    // Check if the gateway actually processed the request with chaos headers
    const hasChaosTelemetry = resHeaders.has('x-panic-colo') && resHeaders.get('x-panic-colo') !== 'UNKNOWN';
    const isGatewayRejection = !hasChaosTelemetry && (status === 401 || status === 403);

    // If gateway itself rejected the token or is unreachable, do not fabricate telemetry and refund quota
    if (!hasChaosTelemetry) {
      const { refundQuota } = await import('@/lib/quota');
      await refundQuota(session.user.id).catch(() => {});

      return NextResponse.json({
        success: false,
        status: status || 503,
        statusText: statusText || 'Service Unavailable',
        isAuthError: isGatewayRejection,
        isGatewayError: true,
        totalLatency: t1_total,
        telemetry: null,
        chaosReason: null,
        chaosClientContext: null,
        mutilatedStrategy: null,
        resolvedIp: payload.targetHost ? (await resolveHostIp(payload.targetHost).catch(() => 'Unresolved')) || 'Unresolved' : 'Unresolved',
        responseBody
      });
    }

    // Extract headers for valid edge chaos telemetry
    const hdrW1 = resHeaders.get('x-panic-w1');
    const hdrW3 = resHeaders.get('x-panic-w3');
    const hdrT2 = resHeaders.get('x-panic-t2');
    const hdrT3 = resHeaders.get('x-panic-t3');

    let w1 = [0, 0];
    let w3 = [0, 0];
    let t2 = 0;
    let t3 = 0;

    if (hdrW1) w1 = hdrW1.split(',').map(Number);
    if (hdrT2) t2 = Math.max(0, Number(hdrT2) || 0);
    if (hdrT3) t3 = Math.max(0, Number(hdrT3) || 0);

    // Fallbacks if data plane headers are missing
    if (!hdrW1) w1 = [-118.2437, 34.0522]; // Mock CF LAX

    // W3 fallback for missing data plane headers
    if (hdrW3 && hdrW3 !== '0,0') {
      w3 = hdrW3.split(',').map(Number);
    } else if (payload.w3 && Array.isArray(payload.w3) && payload.w3.length === 2) {
      w3 = payload.w3;
    } else if (payload.targetHost) {
      try {
        const address = await resolveHostIp(payload.targetHost);
        if (address && !isPrivateIp(address)) {
          const geoRes = await fetch(`https://ipapi.co/${address}/json/`, {
            signal: AbortSignal.timeout(800)
          });
          const geoData = await geoRes.json() as { longitude?: number; latitude?: number };
          if (geoData && typeof geoData.longitude === 'number' && typeof geoData.latitude === 'number') {
            w3 = [geoData.longitude, geoData.latitude];
          } else {
            w3 = [0, 0];
          }
        } else {
          w3 = [0, 0];
        }
      } catch (geoErr) {
        console.warn('Fallback W3 resolution failed:', geoErr);
        w3 = [0, 0];
      }
    } else {
      w3 = [0, 0];
    }

    // Calculate Final Timings
    const t1_total_net = t1_total;
    
    // Calculate one-way trips for visual map scaling
    const t3_visual = t3 / 2; // W2 -> W3 single trip
    let t1_visual = (t1_total_net - t2 - t3) / 2; // W1 -> W2 single trip
    if (t1_visual < 5) t1_visual = 5; // Prevent negative rendering visually

    // Extract colo and abort reasons
    const colo = resHeaders.get('x-panic-colo') || 'UNKNOWN';
    const chaosReason = resHeaders.get('X-Chaos-Reason');
    const chaosClientContext = resHeaders.get('X-Chaos-Client-Context');
    const mutilatedStrategy = resHeaders.get('X-Chaos-Mutilated') || resHeaders.get('x-chaos-mutilated');

    // Resolve IP purely for terminal visual logging
    let resolvedIp = 'Unknown IP';
    if (payload.targetHost) {
      try {
        const address = await resolveHostIp(payload.targetHost);
        resolvedIp = address || 'Unresolved';
      } catch {
        resolvedIp = 'Unresolved';
      }
    }

    // In this CF-to-CF architecture, request.cf is passed through so W1 and W2 share the same physical colo.
    const w1_colo = colo;
    
    return NextResponse.json({
      success: true,
      status,
      statusText,
      isAuthError: false,
      isGatewayError: false,
      totalLatency: t1_total_net,
      telemetry: {
         w1, w3,
         t1: t1_visual,
         t2: t2,
         t3: t3_visual,
         colo,
         w1_colo
      },
      chaosReason,
      chaosClientContext,
      mutilatedStrategy,
      resolvedIp,
      responseBody
    });

  } catch (err) {
    console.error('Test injection error:', err);
    return NextResponse.json({ error: 'Failed to run injection test' }, { status: 500 });
  }
}
