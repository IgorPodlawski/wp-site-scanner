import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import { WP_VERSION_SHAPE } from '../analysis/version-confidence.js';
import {
  ComponentScanner,
  type ComponentScannerConfig,
  type DetectedComponent,
} from './component-scanner.js';

// Layer 3 (audit + deep only): a small, curated list of well-known
// wordpress.org theme slugs, each verified against the live
// api.wordpress.org/themes/info/1.2/ endpoint before being added here.
// Deliberately not a large/generic wordlist per CLAUDE.md's "not a
// brute-force tool" — this exists only to catch a theme that Layer 1 misses
// because its slug never appears in the homepage HTML.
const THEME_DICTIONARY: readonly string[] = [
  'twentytwentyfour',
  'twentytwentythree',
  'twentytwentytwo',
  'twentytwentyone',
  'twentytwenty',
  'twentynineteen',
  'astra',
  'generatepress',
  'oceanwp',
  'neve',
  'kadence',
  'hello-elementor',
  'storefront',
  'blocksy',
];

const THEME_CONFIG: ComponentScannerConfig = {
  name: 'theme-scanner',
  contentPathSegment: 'themes',
  versionProbeFilename: 'style.css',
  versionLinePattern: new RegExp(`^\\s*Version:\\s*(${WP_VERSION_SHAPE})`, 'im'),
  versionSource: 'theme-stylesheet',
  dictionary: THEME_DICTIONARY,
};

export type DetectedTheme = DetectedComponent;

/**
 * Detects the active theme (and any referenced parent/child theme). See
 * ComponentScanner for the shared Layer 1-3 implementation; this file only
 * supplies the theme-specific config (path segment, style.css probing, and
 * the theme dictionary).
 */
export class ThemeScanner extends ComponentScanner {
  constructor(httpClientOptions?: HttpClientOptions, httpClient?: HttpClient) {
    super(THEME_CONFIG, httpClientOptions, httpClient);
  }
}
