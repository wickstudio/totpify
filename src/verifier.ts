import { generateTOTP } from './totp';
import {
  assertDigits,
  assertPeriod,
  assertTimestamp,
  assertWindow,
  constantTimeEqual,
} from './utils';
import {
  CreateVerifierOptions,
  DiagnosticsMode,
  ReplayMarkInput,
  ReplayStatus,
  ReplayStore,
  VerificationContext,
  VerificationDecision,
  VerificationDiagnostics,
  VerificationEvent,
  VerificationPolicy,
  VerificationPolicyName,
  VerificationPolicyOverrides,
  VerificationReason,
  VerificationRequest,
  Verifier,
} from './types';

type RejectionClassification = {
  reason: Exclude<VerificationReason, 'valid'>;
  delta?: number;
};

const policyPresetValues: Record<
  VerificationPolicyName,
  Omit<VerificationPolicy, 'name'>
> = {
  strict: {
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    maxPastSteps: 0,
    maxFutureSteps: 0,
    driftDetectionWindow: 1,
    requireReplayProtection: false,
  },
  balanced: {
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    maxPastSteps: 1,
    maxFutureSteps: 0,
    driftDetectionWindow: 2,
    requireReplayProtection: false,
  },
  admin: {
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    maxPastSteps: 1,
    maxFutureSteps: 0,
    driftDetectionWindow: 3,
    requireReplayProtection: true,
  },
};

export const verificationPolicies: Record<VerificationPolicyName, VerificationPolicy> = {
  strict: { name: 'strict', ...policyPresetValues.strict },
  balanced: { name: 'balanced', ...policyPresetValues.balanced },
  admin: { name: 'admin', ...policyPresetValues.admin },
};

export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();

  async markStep(input: ReplayMarkInput): Promise<'fresh' | 'replay'> {
    this.prune(input.now);

    const key = getReplayKey(input);
    const expiresAt = this.entries.get(key);

    if (typeof expiresAt === 'number' && expiresAt > input.now) {
      return 'replay';
    }

    this.entries.set(key, input.now + input.ttlMs);
    return 'fresh';
  }

  private prune(now: number): void {
    for (const [key, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now) {
        this.entries.delete(key);
      }
    }
  }
}

export function resolveVerificationPolicy(
  policy?: VerificationPolicyName | VerificationPolicyOverrides,
  basePolicy?: VerificationPolicy
): VerificationPolicy {
  let resolved = basePolicy ? { ...basePolicy } : { ...verificationPolicies.balanced };

  if (typeof policy === 'string') {
    resolved = { ...verificationPolicies[policy] };
  } else if (policy) {
    if (policy.preset) {
      resolved = { ...verificationPolicies[policy.preset] };
    }

    const { preset, ...overrides } = policy;
    resolved = { ...resolved, ...overrides };

    if (Object.keys(overrides).length > 0) {
      resolved.name = policy.preset ? policy.preset : 'custom';
    }
  }

  validateVerificationPolicy(resolved);
  return resolved;
}

export function createVerifier(options: CreateVerifierOptions = {}): Verifier {
  const basePolicy = resolveVerificationPolicy(options.policy);
  const defaultDiagnostics = options.diagnostics || 'off';

  return {
    async verify(input: VerificationRequest): Promise<VerificationDecision> {
      const timestamp = input.timestamp ?? Date.now();
      const diagnosticsMode = input.diagnostics ?? defaultDiagnostics;
      const policy = getRequestPolicy(basePolicy, input);
      const currentStep = getCurrentStep(timestamp, policy.period);
      const checkedDeltas = buildCandidateDeltas(policy.maxPastSteps, policy.maxFutureSteps);
      const context = sanitizeContext(input.context);

      assertTimestamp(timestamp);

      if (!input.token || input.token.length !== policy.digits || !/^\d+$/.test(input.token)) {
        return rejectVerification({
          input,
          timestamp,
          currentStep,
          checkedDeltas: [],
          policy,
          reason: 'invalid_format',
          replayStatus: 'skipped',
          diagnosticsMode,
          context,
          onEvent: options.onEvent,
        });
      }

      const matchedDelta = findMatchingDelta(input, policy, timestamp, checkedDeltas);

      if (typeof matchedDelta !== 'number') {
        const rejection = classifyRejectedToken(input, policy, timestamp);
        return rejectVerification({
          input,
          timestamp,
          currentStep,
          checkedDeltas,
          policy,
          reason: rejection.reason,
          classifiedDelta: rejection.delta,
          replayStatus: 'skipped',
          diagnosticsMode,
          context,
          onEvent: options.onEvent,
        });
      }

      const matchedStep = currentStep + BigInt(matchedDelta);
      const expiresInMs = getAcceptanceExpiresInMs(matchedStep, policy.maxPastSteps, policy.period, timestamp);

      let replayStatus: ReplayStatus = 'skipped';

      if (options.replayStore && input.factorId) {
        replayStatus = await options.replayStore.markStep({
          factorId: input.factorId,
          subject: input.subject,
          step: matchedStep,
          ttlMs: expiresInMs,
          now: timestamp,
        });
      } else if (policy.requireReplayProtection) {
        replayStatus = 'required';
      }

      if (replayStatus === 'replay') {
        return rejectVerification({
          input,
          timestamp,
          currentStep,
          checkedDeltas,
          policy,
          reason: 'replay_detected',
          matchedDelta,
          matchedStep,
          expiresInMs,
          replayStatus,
          diagnosticsMode,
          context,
          onEvent: options.onEvent,
        });
      }

      if (replayStatus === 'required') {
        return rejectVerification({
          input,
          timestamp,
          currentStep,
          checkedDeltas,
          policy,
          reason: 'policy_blocked',
          matchedDelta,
          matchedStep,
          expiresInMs,
          replayStatus,
          diagnosticsMode,
          context,
          onEvent: options.onEvent,
        });
      }

      const decision: VerificationDecision = {
        ok: true,
        reason: 'valid',
        deltaSteps: matchedDelta,
        step: matchedStep.toString(),
        expiresInMs,
        replayStatus,
        policy,
        diagnostics: buildDiagnostics({
          mode: diagnosticsMode,
          timestamp,
          currentStep,
          checkedDeltas,
          tokenLength: input.token.length,
          matchedDelta,
          matchedStep,
        }),
      };

      await emitEvent(options.onEvent, {
        type: 'totp.verify',
        timestamp,
        outcome: 'accepted',
        reason: decision.reason,
        factorId: input.factorId,
        subject: input.subject,
        policy: policy.name,
        deltaSteps: decision.deltaSteps,
        step: decision.step,
        replayStatus: decision.replayStatus,
        expiresInMs: decision.expiresInMs,
        context,
      });

      return decision;
    },

    getPolicy(overrides?: VerificationPolicyName | VerificationPolicyOverrides): VerificationPolicy {
      return resolveVerificationPolicy(overrides, basePolicy);
    },
  };
}

function getRequestPolicy(basePolicy: VerificationPolicy, input: VerificationRequest): VerificationPolicy {
  let policy = resolveVerificationPolicy(input.policy, basePolicy);

  if (
    typeof input.algorithm !== 'undefined' ||
    typeof input.digits !== 'undefined' ||
    typeof input.period !== 'undefined'
  ) {
    policy = {
      ...policy,
      algorithm: input.algorithm || policy.algorithm,
      digits: typeof input.digits === 'number' ? input.digits : policy.digits,
      period: typeof input.period === 'number' ? input.period : policy.period,
      name: 'custom',
    };
  }

  validateVerificationPolicy(policy);
  return policy;
}

function validateVerificationPolicy(policy: VerificationPolicy): void {
  assertDigits(policy.digits);
  assertPeriod(policy.period);
  assertWindow(policy.maxPastSteps);
  assertWindow(policy.maxFutureSteps);
  assertWindow(policy.driftDetectionWindow);

  if (!['SHA-1', 'SHA-256', 'SHA-512'].includes(policy.algorithm)) {
    throw new Error(`Unsupported algorithm: ${policy.algorithm}`);
  }
}

function findMatchingDelta(
  input: VerificationRequest,
  policy: VerificationPolicy,
  timestamp: number,
  deltas: number[]
): number | undefined {
  for (const delta of deltas) {
    const generatedToken = generateTOTP(input.secret, {
      algorithm: policy.algorithm,
      digits: policy.digits,
      period: policy.period,
      timestamp: timestamp + delta * policy.period * 1000,
    });

    if (constantTimeEqual(generatedToken, input.token)) {
      return delta;
    }
  }

  return undefined;
}

function classifyRejectedToken(
  input: VerificationRequest,
  policy: VerificationPolicy,
  timestamp: number
): RejectionClassification {
  const pastDeltas = buildClassifiedPastDeltas(policy.maxPastSteps, policy.driftDetectionWindow);
  const expiredDelta = findMatchingDelta(input, policy, timestamp, pastDeltas);

  if (typeof expiredDelta === 'number') {
    return {
      reason: 'expired',
      delta: expiredDelta,
    };
  }

  const futureDeltas = buildClassifiedFutureDeltas(policy.maxFutureSteps, policy.driftDetectionWindow);
  const futureDelta = findMatchingDelta(input, policy, timestamp, futureDeltas);

  if (typeof futureDelta === 'number') {
    return {
      reason: 'future_skew',
      delta: futureDelta,
    };
  }

  return {
    reason: 'invalid_token',
  };
}

async function rejectVerification(input: {
  input: VerificationRequest;
  timestamp: number;
  currentStep: bigint;
  checkedDeltas: number[];
  policy: VerificationPolicy;
  reason: Exclude<VerificationReason, 'valid'>;
  matchedDelta?: number;
  matchedStep?: bigint;
  classifiedDelta?: number;
  expiresInMs?: number;
  replayStatus: ReplayStatus;
  diagnosticsMode: DiagnosticsMode;
  context?: VerificationContext;
  onEvent?: (event: VerificationEvent) => void | Promise<void>;
}): Promise<VerificationDecision> {
  const decision: VerificationDecision = {
    ok: false,
    reason: input.reason,
    deltaSteps: input.matchedDelta,
    step: typeof input.matchedStep === 'bigint' ? input.matchedStep.toString() : undefined,
    expiresInMs: input.expiresInMs,
    replayStatus: input.replayStatus,
    policy: input.policy,
    diagnostics: buildDiagnostics({
      mode: input.diagnosticsMode,
      timestamp: input.timestamp,
      currentStep: input.currentStep,
      checkedDeltas: input.checkedDeltas,
      tokenLength: input.input.token.length,
      matchedDelta: input.matchedDelta,
      matchedStep: input.matchedStep,
      classifiedReason: input.reason,
      classifiedDelta: input.classifiedDelta,
    }),
  };

  await emitEvent(input.onEvent, {
    type: 'totp.verify',
    timestamp: input.timestamp,
    outcome: 'rejected',
    reason: decision.reason,
    factorId: input.input.factorId,
    subject: input.input.subject,
    policy: input.policy.name,
    deltaSteps: decision.deltaSteps,
    step: decision.step,
    replayStatus: decision.replayStatus,
    expiresInMs: decision.expiresInMs,
    context: input.context,
  });

  return decision;
}

function buildDiagnostics(input: {
  mode: DiagnosticsMode;
  timestamp: number;
  currentStep: bigint;
  checkedDeltas: number[];
  tokenLength: number;
  matchedDelta?: number;
  matchedStep?: bigint;
  classifiedReason?: Exclude<VerificationReason, 'valid'>;
  classifiedDelta?: number;
}): VerificationDiagnostics | undefined {
  if (input.mode === 'off') {
    return undefined;
  }

  return {
    mode: input.mode,
    evaluatedAt: input.timestamp,
    currentStep: input.currentStep.toString(),
    checkedDeltas: input.checkedDeltas,
    matchedDelta: input.matchedDelta,
    matchedStep: typeof input.matchedStep === 'bigint' ? input.matchedStep.toString() : undefined,
    classifiedReason: input.classifiedReason,
    classifiedDelta: input.classifiedDelta,
    tokenLength: input.tokenLength,
  };
}

async function emitEvent(
  onEvent: CreateVerifierOptions['onEvent'],
  event: VerificationEvent
): Promise<void> {
  if (!onEvent) {
    return;
  }

  try {
    await Promise.resolve(onEvent(event));
  } catch {
    return;
  }
}

function sanitizeContext(context: VerificationContext | undefined): VerificationContext | undefined {
  if (!context) {
    return undefined;
  }

  const safeContext: VerificationContext = {};

  for (const [key, value] of Object.entries(context)) {
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null
    ) {
      safeContext[key] = value;
    }
  }

  return Object.keys(safeContext).length > 0 ? safeContext : undefined;
}

function buildCandidateDeltas(maxPastSteps: number, maxFutureSteps: number): number[] {
  const deltas = [0];
  const edge = Math.max(maxPastSteps, maxFutureSteps);

  for (let step = 1; step <= edge; step++) {
    if (step <= maxPastSteps) {
      deltas.push(-step);
    }

    if (step <= maxFutureSteps) {
      deltas.push(step);
    }
  }

  return deltas;
}

function buildClassifiedPastDeltas(maxPastSteps: number, driftDetectionWindow: number): number[] {
  const deltas: number[] = [];

  for (let step = maxPastSteps + 1; step <= maxPastSteps + driftDetectionWindow; step++) {
    deltas.push(-step);
  }

  return deltas;
}

function buildClassifiedFutureDeltas(maxFutureSteps: number, driftDetectionWindow: number): number[] {
  const deltas: number[] = [];

  for (let step = maxFutureSteps + 1; step <= maxFutureSteps + driftDetectionWindow; step++) {
    deltas.push(step);
  }

  return deltas;
}

function getCurrentStep(timestamp: number, period: number): bigint {
  return BigInt(Math.floor(timestamp / 1000 / period));
}

function getAcceptanceExpiresInMs(
  matchedStep: bigint,
  maxPastSteps: number,
  period: number,
  timestamp: number
): number {
  const acceptanceExpiresAt =
    Number(matchedStep + BigInt(maxPastSteps) + 1n) * period * 1000;

  return Math.max(1, acceptanceExpiresAt - timestamp);
}

function getReplayKey(input: ReplayMarkInput): string {
  return `${input.factorId}:${input.subject || ''}:${input.step.toString()}`;
}
