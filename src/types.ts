export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface TOTPOptions {
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
  timestamp?: number;
  window?: number;
}

export interface QRCodeOptions {
  issuer?: string;
  account?: string;
  width?: number;
  height?: number;
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
}

export type VerifyResult = {
  valid: boolean;
  delta?: number;
};

export interface OtpauthUriOptions {
  issuer?: string;
  account?: string;
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
}

export interface ParsedOtpauthUri {
  type: 'totp';
  label: string;
  issuer: string;
  account: string;
  secret: string;
  algorithm: HashAlgorithm;
  digits: number;
  period: number;
}

export interface RecoveryCodeOptions {
  count?: number;
  segments?: number;
  segmentLength?: number;
  separator?: string;
}

export interface RecoveryCodeHashOptions {
  salt?: string;
  keyLength?: number;
  cost?: number;
  blockSize?: number;
  parallelization?: number;
}

export interface RecoveryCodeSet {
  codes: string[];
  hashes: string[];
}

export interface EnrollmentBundleOptions {
  issuer?: string;
  account?: string;
  secret?: string;
  secretBytes?: number;
  secretByteLength?: number;
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
  qrCode?: boolean | Pick<QRCodeOptions, 'width' | 'height'>;
  recoveryCodes?: boolean | RecoveryCodeOptions;
}

export interface EnrollmentBundle {
  issuer: string;
  account: string;
  secret: string;
  secretBytes: Uint8Array;
  otpauthUri: string;
  qrCodeDataUrl?: string;
  recoveryCodes?: string[];
  recoveryCodeHashes?: string[];
  algorithm: HashAlgorithm;
  digits: number;
  period: number;
  createdAt: number;
}

export type VerificationPolicyName = 'strict' | 'balanced' | 'admin';

export type DiagnosticsMode = 'off' | 'safe' | 'debug';

export type VerificationReason =
  | 'valid'
  | 'invalid_format'
  | 'invalid_token'
  | 'expired'
  | 'future_skew'
  | 'replay_detected'
  | 'policy_blocked';

export type ReplayStatus = 'fresh' | 'replay' | 'skipped' | 'required';

export type VerificationContextValue = string | number | boolean | null;

export type VerificationContext = Record<string, VerificationContextValue>;

export interface VerificationPolicy {
  name: VerificationPolicyName | 'custom';
  algorithm: HashAlgorithm;
  digits: number;
  period: number;
  maxPastSteps: number;
  maxFutureSteps: number;
  driftDetectionWindow: number;
  requireReplayProtection: boolean;
}

export interface VerificationPolicyOverrides extends Partial<Omit<VerificationPolicy, 'name'>> {
  preset?: VerificationPolicyName;
}

export interface ReplayMarkInput {
  factorId: string;
  subject?: string;
  step: bigint;
  ttlMs: number;
  now: number;
}

export interface ReplayStore {
  markStep(input: ReplayMarkInput): Promise<'fresh' | 'replay'>;
}

export interface VerificationDiagnostics {
  mode: Exclude<DiagnosticsMode, 'off'>;
  evaluatedAt: number;
  currentStep: string;
  checkedDeltas: number[];
  matchedDelta?: number;
  matchedStep?: string;
  classifiedReason?: Exclude<VerificationReason, 'valid'>;
  classifiedDelta?: number;
  tokenLength: number;
}

export interface VerificationDecision {
  ok: boolean;
  reason: VerificationReason;
  deltaSteps?: number;
  step?: string;
  expiresInMs?: number;
  replayStatus: ReplayStatus;
  policy: VerificationPolicy;
  diagnostics?: VerificationDiagnostics;
}

export interface VerificationEvent {
  type: 'totp.verify';
  timestamp: number;
  outcome: 'accepted' | 'rejected';
  reason: VerificationReason;
  factorId?: string;
  subject?: string;
  policy: VerificationPolicy['name'];
  deltaSteps?: number;
  step?: string;
  replayStatus: ReplayStatus;
  expiresInMs?: number;
  context?: VerificationContext;
}

export interface CreateVerifierOptions {
  policy?: VerificationPolicyName | VerificationPolicyOverrides;
  replayStore?: ReplayStore;
  diagnostics?: DiagnosticsMode;
  onEvent?: (event: VerificationEvent) => void | Promise<void>;
}

export interface VerificationRequest {
  token: string;
  secret: string | Uint8Array;
  timestamp?: number;
  factorId?: string;
  subject?: string;
  context?: VerificationContext;
  policy?: VerificationPolicyName | VerificationPolicyOverrides;
  diagnostics?: DiagnosticsMode;
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
}

export interface Verifier {
  verify(input: VerificationRequest): Promise<VerificationDecision>;
  getPolicy(overrides?: VerificationPolicyName | VerificationPolicyOverrides): VerificationPolicy;
}
