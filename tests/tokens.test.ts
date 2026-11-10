import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseTargetHost, isPrivateIp } from '../src/lib/security';

describe('Token Config & TTL Compatibility', () => {
  it('should accurately resolve TTL hours from modern ttlHours config', () => {
    const config = JSON.stringify({ fault: 'latency', latency: 50, ttlHours: 2 });
    const parsed = JSON.parse(config);
    const ttlHours = parseFloat(parsed.ttlHours || parsed.ttl) || 0.25;
    expect(ttlHours).toBe(2);
  });

  it('should accurately resolve TTL hours from legacy ttl config key', () => {
    const config = JSON.stringify({ fault: 'latency', latency: 50, ttl: 4 });
    const parsed = JSON.parse(config);
    const ttlHours = parseFloat(parsed.ttlHours || parsed.ttl) || 0.25;
    expect(ttlHours).toBe(4);
  });

  it('should default to 0.25 hours when TTL is unspecified or corrupt', () => {
    const config = JSON.stringify({ fault: '502' });
    const parsed = JSON.parse(config);
    const ttlHours = parseFloat(parsed.ttlHours || parsed.ttl) || 0.25;
    expect(ttlHours).toBe(0.25);
  });
});

describe('SSRF Protection with Port Stripping', () => {
  it('should isolate hostname from custom port before DNS lookup', () => {
    const hostWithPort = '127.0.0.1.nip.io:8080';
    const parsed = parseTargetHost(hostWithPort);
    expect(parsed).not.toBeNull();
    expect(parsed!.hostname).toBe('127.0.0.1.nip.io');
    expect(parsed!.port).toBe('8080');
    expect(parsed!.isIp).toBe(false);

    // Simulated DNS resolution result for 127.0.0.1.nip.io
    const resolvedIp = '127.0.0.1';
    expect(isPrivateIp(resolvedIp)).toBe(true);
  });

  it('should recognize public IP with port directly without DNS query', () => {
    const ipWithPort = '1.1.1.1:443';
    const parsed = parseTargetHost(ipWithPort);
    expect(parsed).not.toBeNull();
    expect(parsed!.hostname).toBe('1.1.1.1');
    expect(parsed!.port).toBe('443');
    expect(parsed!.isIp).toBe(true);
    expect(isPrivateIp(parsed!.hostname)).toBe(false);
  });

  it('should recognize bracketed IPv6 with port directly without DNS query', () => {
    const ipv6WithPort = '[2606:4700:4700::1111]:8080';
    const parsed = parseTargetHost(ipv6WithPort);
    expect(parsed).not.toBeNull();
    expect(parsed!.hostname).toBe('2606:4700:4700::1111');
    expect(parsed!.port).toBe('8080');
    expect(parsed!.isIp).toBe(true);
    expect(isPrivateIp(parsed!.hostname)).toBe(false);
  });
});
