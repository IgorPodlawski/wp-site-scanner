import type { Scanner } from '../core/types/index.js';
import type { AppConfig } from '../config/types.js';
import type { HttpClientOptions } from '../core/http/http-client.js';
import { HttpScanner } from './http-scanner.js';
import { UndiciHttpClient } from '../core/http/http-client.js';
import { WordPressDetector } from './wordpress-detector.js';
import { CoreVersionScanner } from './core-version-scanner.js';
import { PluginScanner } from './plugin-scanner.js';
import { ThemeScanner } from './theme-scanner.js';
import { EndpointScanner } from './endpoint-scanner.js';
import { HeaderScanner } from './header-scanner.js';
import { TlsScanner } from './tls-scanner.js';

/**
 * Single place scanners are constructed. The orchestrator consumes the
 * returned list and filters by minAuthorization — it never imports concrete
 * scanners directly. A factory (rather than a static list) because
 * HttpScanner needs the run's HTTP limits/User-Agent, which only exist once
 * config is loaded.
 */
export function createScanners(config: AppConfig): Scanner[] {
  const httpClientOptions: HttpClientOptions = {
    timeoutMs: config.HTTP_TIMEOUT_MS,
    maxRedirects: config.MAX_REDIRECTS,
    maxResponseBytes: config.MAX_RESPONSE_BYTES,
    userAgent: config.AUDIT_USER_AGENT,
  };

  return [
    new HttpScanner(httpClientOptions),
    new WordPressDetector(),
    new CoreVersionScanner(),
    new PluginScanner(httpClientOptions, new UndiciHttpClient()),
    new ThemeScanner(),
    new EndpointScanner(),
    new HeaderScanner(),
    new TlsScanner(),
  ];
}
