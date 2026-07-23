import { describe, expect, it } from 'vitest';
import { isSafeToFetch } from '@core/http/ssrf-guard.js';

describe('isSafeToFetch', () => {
  it('allows a public https URL', () => {
    expect(isSafeToFetch(new URL('https://example.com')).safe).toBe(true);
  });

  it('rejects loopback (127.0.0.1)', () => {
    expect(isSafeToFetch(new URL('http://127.0.0.1')).safe).toBe(false);
  });

  it('rejects the "localhost" hostname', () => {
    expect(isSafeToFetch(new URL('http://localhost')).safe).toBe(false);
  });

  it('rejects private IPv4 (10.0.0.0/8)', () => {
    expect(isSafeToFetch(new URL('http://10.1.2.3')).safe).toBe(false);
  });

  it('rejects the cloud metadata address (169.254.169.254)', () => {
    expect(isSafeToFetch(new URL('http://169.254.169.254')).safe).toBe(false);
  });

  it('rejects IPv6 loopback (::1)', () => {
    expect(isSafeToFetch(new URL('http://[::1]')).safe).toBe(false);
  });

  it('rejects disallowed schemes', () => {
    expect(isSafeToFetch(new URL('file:///etc/passwd')).safe).toBe(false);
  });
});
