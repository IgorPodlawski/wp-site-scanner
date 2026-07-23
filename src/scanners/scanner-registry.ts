import type { Scanner } from '../core/types/index.js';
import { HttpScanner } from './http-scanner.js';
import { WordPressDetector } from './wordpress-detector.js';
import { CoreVersionScanner } from './core-version-scanner.js';
import { PluginScanner } from './plugin-scanner.js';
import { ThemeScanner } from './theme-scanner.js';
import { EndpointScanner } from './endpoint-scanner.js';
import { HeaderScanner } from './header-scanner.js';
import { TlsScanner } from './tls-scanner.js';

/**
 * Single place scanners are registered. The orchestrator consumes this list
 * and filters by minAuthorization — it never imports concrete scanners
 * directly.
 */
export const ALL_SCANNERS: Scanner[] = [
  new HttpScanner(),
  new WordPressDetector(),
  new CoreVersionScanner(),
  new PluginScanner(),
  new ThemeScanner(),
  new EndpointScanner(),
  new HeaderScanner(),
  new TlsScanner(),
];
