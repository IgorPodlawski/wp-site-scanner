/** Axis 1 — the hard authorization boundary. Never conflate with IntensityProfile. */
export type AuthorizationMode = 'prospect' | 'audit';

/** Axis 2 — how thorough, always bounded by AuthorizationMode. */
export type IntensityProfile = 'quick' | 'standard' | 'deep';
