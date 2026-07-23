import tls from 'node:tls';
import { UnreachableTargetError } from '../errors.js';

export interface TlsProbeOptions {
  hostname: string;
  resolvedIp: string;
  port: number;
  timeoutMs: number;
}

export interface TlsProbeResult {
  protocol: string | null;
  authorized: boolean;
  authorizationError?: string;
  validFrom?: string;
  validTo?: string;
  subject?: string;
  issuer?: string;
}

export interface TlsProbe {
  probe(options: TlsProbeOptions): Promise<TlsProbeResult>;
}

function firstCommonName(commonName: string | string[] | undefined): string | undefined {
  return Array.isArray(commonName) ? commonName[0] : commonName;
}

/**
 * Opens a direct TLS connection (bypassing the HTTP client entirely — this
 * is about inspecting the handshake itself, not fetching a body) pinned to
 * an already SSRF-validated IP, with the original hostname kept for SNI.
 * `rejectUnauthorized: false` is deliberate: an expired or self-signed
 * certificate is itself the observation we want to report, not a reason to
 * fail the connection.
 */
export class NodeTlsProbe implements TlsProbe {
  probe(options: TlsProbeOptions): Promise<TlsProbeResult> {
    return new Promise((resolve, reject) => {
      const target = `${options.hostname}:${options.port}`;
      const socket = tls.connect({
        host: options.resolvedIp,
        servername: options.hostname,
        port: options.port,
        rejectUnauthorized: false,
        timeout: options.timeoutMs,
      });

      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate();
        const subject = firstCommonName(cert?.subject?.CN);
        const issuer = firstCommonName(cert?.issuer?.CN);
        resolve({
          protocol: socket.getProtocol(),
          authorized: socket.authorized,
          ...(socket.authorized ? {} : { authorizationError: String(socket.authorizationError) }),
          ...(cert?.valid_from ? { validFrom: cert.valid_from } : {}),
          ...(cert?.valid_to ? { validTo: cert.valid_to } : {}),
          ...(subject ? { subject } : {}),
          ...(issuer ? { issuer } : {}),
        });
        socket.end();
      });

      socket.once('timeout', () => {
        socket.destroy();
        reject(new UnreachableTargetError(target, new Error('TLS handshake timed out.')));
      });

      socket.once('error', (cause) => {
        reject(new UnreachableTargetError(target, cause));
      });
    });
  }
}
