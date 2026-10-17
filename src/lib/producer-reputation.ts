/**
 * Fields returned by the public /v1/verify and /v1/blue-tick reputation
 * object; see the API docs.
 *
 * This module validates that object against the shapes the registry returns
 * and projects it to a closed type. Callers project through
 * `projectProducerReputation`, bind the tick with `tickMatchesReputation`,
 * and never pass the original value on.
 */

export const MEASURED_CALIBRATION_STAGES = [
  "uncalibrated",
  "declared",
  "cohort",
  "basic",
  "full",
  "degenerate",
] as const;

export const CALIBRATION_STAGES = ["unseen", ...MEASURED_CALIBRATION_STAGES] as const;

export type MeasuredCalibrationStage = (typeof MEASURED_CALIBRATION_STAGES)[number];
export type CalibrationStage = (typeof CALIBRATION_STAGES)[number];

const STAGE_SET: ReadonlySet<string> = new Set(CALIBRATION_STAGES);
const MEASURED_STAGE_SET: ReadonlySet<string> = new Set(MEASURED_CALIBRATION_STAGES);
const POSITIVE_TICK_STAGE_SET: ReadonlySet<MeasuredCalibrationStage> = new Set([
  "basic",
  "full",
]);

const REPUTATION_KEYS = [
  "entropy_score",
  "drift_detected",
  "z_score",
  "calibration_stage",
] as const;

export type UnseenProducerReputation = {
  entropy_score: null;
  drift_detected: false;
  z_score: null;
  calibration_stage: "unseen";
};

export type MeasuredProducerReputation = {
  entropy_score: number | null;
  drift_detected: boolean;
  z_score: number;
  calibration_stage: MeasuredCalibrationStage;
};

export type ProducerReputation = UnseenProducerReputation | MeasuredProducerReputation;

/** The exact no-claim reputation the registry returns for an unmeasured agent. */
export const UNSEEN_REPUTATION: UnseenProducerReputation = {
  entropy_score: null,
  drift_detected: false,
  z_score: null,
  calibration_stage: "unseen",
};

export function isCalibrationStage(value: unknown): value is CalibrationStage {
  return typeof value === "string" && STAGE_SET.has(value);
}

export function isMeasuredCalibrationStage(value: unknown): value is MeasuredCalibrationStage {
  return typeof value === "string" && MEASURED_STAGE_SET.has(value);
}

/**
 * The client accepts an entropy score in [0,1] or null, and a z-score that is
 * a finite, non-negative number.
 */
function isNullableEntropyScore(value: unknown): value is number | null {
  return (
    value === null ||
    (typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1)
  );
}

function isNonNegativeFiniteScore(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isUnseenReputationShape(r: Record<string, unknown>): boolean {
  return (
    r.calibration_stage === "unseen" &&
    r.entropy_score === null &&
    r.z_score === null &&
    r.drift_detected === false
  );
}

/**
 * Typed projection of the four reputation fields, or `null` if the value is
 * not a body the registry can return.
 *
 * Extra keys are ignored on input and never copied out; the original object
 * does not pass through. Anything that does not match a returned shape fails
 * closed.
 */
export function projectProducerReputation(value: unknown): ProducerReputation | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const r = value as Record<string, unknown>;
  for (const key of REPUTATION_KEYS) {
    if (!(key in r)) return null;
  }
  if (typeof r.drift_detected !== "boolean") return null;

  if (r.calibration_stage === "unseen") {
    if (!isUnseenReputationShape(r)) return null;
    return { ...UNSEEN_REPUTATION };
  }
  if (!isMeasuredCalibrationStage(r.calibration_stage)) return null;
  if (!isNullableEntropyScore(r.entropy_score) || !isNonNegativeFiniteScore(r.z_score)) {
    return null;
  }
  return {
    entropy_score: r.entropy_score,
    drift_detected: r.drift_detected,
    z_score: r.z_score,
    calibration_stage: r.calibration_stage,
  };
}

/** Whether the tick is consistent with the reputation fields as the registry returns them. */
export function tickMatchesReputation(
  blueTick: boolean,
  reputation: ProducerReputation
): boolean {
  if (reputation.calibration_stage === "unseen") return blueTick === false;
  if (!blueTick) return true;
  return (
    reputation.drift_detected === false &&
    typeof reputation.entropy_score === "number" &&
    Number.isFinite(reputation.entropy_score) &&
    reputation.entropy_score >= 0 &&
    reputation.entropy_score <= 1 &&
    reputation.z_score >= 0 &&
    POSITIVE_TICK_STAGE_SET.has(reputation.calibration_stage)
  );
}
