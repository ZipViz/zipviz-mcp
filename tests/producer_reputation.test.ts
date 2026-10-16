import { describe, expect, it } from "vitest";

import {
  CALIBRATION_STAGES,
  MEASURED_CALIBRATION_STAGES,
  UNSEEN_REPUTATION,
  isCalibrationStage,
  projectProducerReputation,
  tickMatchesReputation,
} from "../src/lib/producer-reputation.js";

/**
 * The four-field reputation object the registry copies from the behavior service.
 * Numbers taken from the registry tests.
 */
const FULL = {
  entropy_score: 0.42,
  drift_detected: false,
  z_score: 1.1,
  calibration_stage: "full" as const,
};

describe("projectProducerReputation — producer contract", () => {
  it("projects only the four reputation fields", () => {
    const projected = projectProducerReputation({
      ...FULL,
      extra_number: 191,
      extra_label: "anything",
      injected: true,
    });
    expect(projected).toEqual(FULL);
    expect(projected).not.toHaveProperty("extra_number");
    expect(projected).not.toHaveProperty("extra_label");
    expect(projected).not.toHaveProperty("injected");
  });

  it.each([...MEASURED_CALIBRATION_STAGES])("accepts measured stage %s with measured scores", (stage) => {
    expect(projectProducerReputation({ ...FULL, calibration_stage: stage })).toEqual({
      ...FULL,
      calibration_stage: stage,
    });
  });

  it("accepts the exact unseen no-claim shape the registry returns", () => {
    expect(projectProducerReputation({ ...UNSEEN_REPUTATION })).toEqual(UNSEEN_REPUTATION);
  });

  it("accepts null entropy on a measured negative but requires a finite measured z-score", () => {
    expect(projectProducerReputation({ ...FULL, entropy_score: null })).toEqual({
      ...FULL,
      entropy_score: null,
    });
    expect(projectProducerReputation({ ...FULL, z_score: null })).toBeNull();
  });

  it("rejects unseen mixed with measured scores or drift", () => {
    expect(projectProducerReputation({ ...FULL, calibration_stage: "unseen" })).toBeNull();
    expect(
      projectProducerReputation({ ...UNSEEN_REPUTATION, entropy_score: 0.42 })
    ).toBeNull();
    expect(projectProducerReputation({ ...UNSEEN_REPUTATION, z_score: 1.1 })).toBeNull();
    expect(
      projectProducerReputation({ ...UNSEEN_REPUTATION, drift_detected: true })
    ).toBeNull();
  });

  it.each(["calibrated", "calibrating", "pending", "Full", "CALIBRATED", ""])(
    "rejects invented stage %j",
    (stage) => {
      expect(projectProducerReputation({ ...FULL, calibration_stage: stage })).toBeNull();
      expect(isCalibrationStage(stage)).toBe(false);
    }
  );

  it.each([
    ["NaN entropy", { ...FULL, entropy_score: Number.NaN }],
    ["Infinity entropy", { ...FULL, entropy_score: Number.POSITIVE_INFINITY }],
    ["negative entropy", { ...FULL, entropy_score: -0.01 }],
    ["entropy above one", { ...FULL, entropy_score: 1.01 }],
    ["-Infinity z", { ...FULL, z_score: Number.NEGATIVE_INFINITY }],
    ["NaN z", { ...FULL, z_score: Number.NaN }],
    ["negative z", { ...FULL, z_score: -0.01 }],
  ])("rejects out-of-contract score (%s)", (_label, value) => {
    expect(projectProducerReputation(value)).toBeNull();
  });

  it.each([null, undefined, "full", 3, true, [], [{ ...FULL }]])(
    "rejects malformed value %j",
    (value) => {
      expect(projectProducerReputation(value)).toBeNull();
    }
  );

  it("lists unseen plus the measured ladder and nothing else", () => {
    expect(CALIBRATION_STAGES).toEqual(["unseen", ...MEASURED_CALIBRATION_STAGES]);
  });
});

describe("tickMatchesReputation — producer gate", () => {
  it("allows a tick only on BASIC/FULL with finite scores and no drift", () => {
    expect(tickMatchesReputation(true, FULL)).toBe(true);
    expect(tickMatchesReputation(true, { ...FULL, calibration_stage: "basic" })).toBe(true);
    expect(tickMatchesReputation(false, FULL)).toBe(true);
    expect(tickMatchesReputation(false, { ...FULL, drift_detected: true })).toBe(true);
    expect(tickMatchesReputation(true, { ...FULL, drift_detected: true })).toBe(false);
    expect(tickMatchesReputation(true, { ...FULL, entropy_score: null })).toBe(false);
    expect(tickMatchesReputation(true, { ...FULL, entropy_score: -0.01 })).toBe(false);
    expect(tickMatchesReputation(true, { ...FULL, entropy_score: 1.01 })).toBe(false);
    expect(tickMatchesReputation(true, { ...FULL, z_score: -0.01 })).toBe(false);
    for (const calibration_stage of ["uncalibrated", "declared", "cohort", "degenerate"] as const) {
      expect(tickMatchesReputation(true, { ...FULL, calibration_stage })).toBe(false);
      expect(tickMatchesReputation(false, { ...FULL, calibration_stage })).toBe(true);
    }
  });

  it("allows unseen only as a negative", () => {
    expect(tickMatchesReputation(false, UNSEEN_REPUTATION)).toBe(true);
    expect(tickMatchesReputation(true, UNSEEN_REPUTATION)).toBe(false);
  });
});
