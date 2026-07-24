import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import { WP_VERSION_SHAPE } from '../analysis/version-confidence.js';
import {
  ComponentScanner,
  type ComponentScannerConfig,
  type DetectedComponent,
} from './component-scanner.js';

// Layer 3 (audit + deep only): a small, curated list of well-known
// wordpress.org plugin slugs, each verified against the live
// api.wordpress.org/plugins/info/1.0/ endpoint before being added here — a
// typo'd slug would just silently never match anything, so accuracy matters
// more than coverage. Deliberately not a large/generic wordlist per
// CLAUDE.md's "not a brute-force tool" — this exists only to catch plugins
// that Layer 1 misses because their slug never appears in the homepage HTML.
const PLUGIN_DICTIONARY: readonly string[] = [
  'akismet',
  'woocommerce',
  'elementor',
  'wordpress-seo',
  'contact-form-7',
  'jetpack',
  'wp-super-cache',
  'updraftplus',
  'wordfence',
  'all-in-one-seo-pack',
  'classic-editor',
  'wpforms-lite',
  'mailchimp-for-wp',
  'duplicate-post',
  'redirection',
  'wp-mail-smtp',
  'tablepress',
  'really-simple-ssl',
  'litespeed-cache',
  'advanced-custom-fields',
  'w3-total-cache',
  'google-analytics-for-wordpress',
  'autoptimize',
  'wp-optimize',
  'wp-smushit',
  'ninja-forms',
  'wp-fastest-cache',
  'woocommerce-services',
  'google-site-kit',
  'polylang',
  'loco-translate',
  'cookie-notice',
  'complianz-gdpr',
  'wp-google-maps',
  'envira-gallery-lite',
  'regenerate-thumbnails',
  'limit-login-attempts-reloaded',
  'really-simple-captcha',
  'wp-user-avatar',
  'broken-link-checker',
  'query-monitor',
  'code-snippets',
  'custom-post-type-ui',
  'mailpoet',
  'the-events-calendar',
  'buddypress',
  'bbpress',
  'amp',
  'seo-by-rank-math',
  'insert-headers-and-footers',
  'wp-statistics',
  'user-registration',
];

const PLUGIN_CONFIG: ComponentScannerConfig = {
  name: 'plugin-scanner',
  contentPathSegment: 'plugins',
  versionProbeFilename: 'readme.txt',
  versionLinePattern: new RegExp(`Stable tag:\\s*(${WP_VERSION_SHAPE})`, 'i'),
  versionSource: 'plugin-readme',
  dictionary: PLUGIN_DICTIONARY,
};

export type DetectedPlugin = DetectedComponent;

/**
 * Detects installed plugins. See ComponentScanner for the shared Layer 1-3
 * implementation; this file only supplies the plugin-specific config
 * (path segment, readme.txt probing, and the plugin dictionary).
 */
export class PluginScanner extends ComponentScanner {
  constructor(httpClientOptions?: HttpClientOptions, httpClient?: HttpClient) {
    super(PLUGIN_CONFIG, httpClientOptions, httpClient);
  }
}
