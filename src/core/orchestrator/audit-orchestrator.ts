import type {
  Scanner,
  AuthorizationMode,
  ConsentArtifact,
  Target,
  AuditResult,
} from '../types/index.js';
import type { AuditRequest } from './audit-request.js';
import type { AppConfig } from '../../config/types.js';
import type { Logger } from '../../utils/logger.js';
import { buildTarget } from '../types/target.js';
import { MissingConsentError, NotImplementedError } from '../errors.js';

const AUTH_RANK: Record<AuthorizationMode, number> = { prospect: 0, audit: 1 };

/**
 * Filters scanners by the active authorization mode. This is the mechanical
 * enforcement of "the orchestrator filters scanners by minAuthorization
 * before running them" — a scanner requiring 'audit' must never run under
 * 'prospect', even if constructed and called by mistake elsewhere.
 */
export function filterScannersByAuthorization(
  scanners: readonly Scanner[],
  mode: AuthorizationMode,
): Scanner[] {
  const modeRank = AUTH_RANK[mode];
  return scanners.filter((scanner) => AUTH_RANK[scanner.minAuthorization] <= modeRank);
}

export interface ResolvedAuthorization {
  mode: AuthorizationMode;
  consentArtifact?: ConsentArtifact;
}

/**
 * Resolves the requested mode against the consent gate. Fails fast — never
 * silently downgrades audit to prospect when consent is missing.
 */
export function resolveAuthorizationMode(
  request: AuditRequest,
  target: Target,
): ResolvedAuthorization {
  if (request.requestedMode === 'prospect') {
    return { mode: 'prospect' };
  }

  if (!request.consent?.confirmed) {
    throw new MissingConsentError(target.domain);
  }

  const consentArtifact: ConsentArtifact = {
    targetDomain: target.domain,
    confirmed: true,
    timestamp: new Date().toISOString(),
    ...(request.consent.operatorNote !== undefined
      ? { operatorNote: request.consent.operatorNote }
      : {}),
    source: request.consent.source,
  };

  return { mode: 'audit', consentArtifact };
}

/**
 * Coordinates the audit. Does NOT perform technical analysis — that is the
 * scanners' job. See CLAUDE.md "Audit pipeline" for the full 19-step
 * sequence this will eventually run; only the pure, I/O-free steps
 * (authorization resolution, scanner filtering) are implemented for real
 * here. Everything requiring network I/O, WordPress detection, findings,
 * scoring, or report generation is Phase 1+ feature work.
 */
export class AuditOrchestrator {
  constructor(
    private readonly scanners: readonly Scanner[],
    private readonly config: AppConfig,
    private readonly logger: Logger,
  ) {}

  filterScanners(mode: AuthorizationMode): Scanner[] {
    return filterScannersByAuthorization(this.scanners, mode);
  }

  async run(request: AuditRequest): Promise<AuditResult> {
    // Step 1: Validate target — real (pure parsing, no I/O).
    const target = buildTarget(request.targetInput);

    // Step 4: Resolve authorization mode + consent gate — real. Fails fast
    // on missing consent; never silently downgrades audit to prospect.
    const { mode } = resolveAuthorizationMode(request, target);
    this.filterScanners(mode);

    // TODO (Phase 1 feature work) — remaining pipeline steps (see CLAUDE.md "Audit pipeline"):
    //  2. SSRF protection
    //  3. Resolve DNS
    //  5. Fetch homepage
    //  6. Detect WordPress (short-circuit if not WP)
    //  7. Detect core version
    //  8. Detect plugins
    //  9. Detect theme
    // 10. Check public endpoints (audit only)
    // 11. Check security headers
    // 12. Check TLS
    // 13. Enrich via external APIs
    // 14. Generate findings
    // 15. Calculate scores
    // 16. Generate sales insights
    // 17. Save JSON
    // 18. Generate HTML
    // 19. Generate PDF
    throw new NotImplementedError(
      'AuditOrchestrator.run (Phase 1 feature work beyond authorization resolution)',
    );
  }
}
