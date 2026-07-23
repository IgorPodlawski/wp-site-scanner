/** Base class for target-level failures. These map an audit run to AuditStatus 'failed'. */
export abstract class AuditFailureError extends Error {}

export class InvalidTargetError extends AuditFailureError {
  constructor(input: string, reason: string) {
    super(`Invalid target "${input}": ${reason}`);
    this.name = 'InvalidTargetError';
  }
}

export class SsrfRejectedError extends AuditFailureError {
  constructor(url: string, reason: string) {
    super(`Refusing to fetch "${url}": ${reason}`);
    this.name = 'SsrfRejectedError';
  }
}

export class MissingConsentError extends AuditFailureError {
  constructor(domain: string) {
    super(
      `Audit mode requires a consent artifact for "${domain}" ` +
        '(--i-have-authorization or a populated batch "consent" column). ' +
        'Refusing to silently downgrade to prospect mode.',
    );
    this.name = 'MissingConsentError';
  }
}

export class UnreachableTargetError extends AuditFailureError {
  constructor(url: string, cause?: unknown) {
    super(`Unreachable target "${url}"`);
    this.name = 'UnreachableTargetError';
    this.cause = cause;
  }
}

export class NotImplementedError extends Error {
  constructor(what: string) {
    super(`Not implemented: ${what}`);
    this.name = 'NotImplementedError';
  }
}
