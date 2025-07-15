/**
 * k6 script for the complete ZK‑Auth flow
 * Three ready‑made load profiles:
 *   - easyOptions   (light smoke test)
 *   - mediumOptions (average expected load)
 *   - hardOptions   (stress test)
 *
 * To switch profile, comment/uncomment the `export const options = …` lines
 * at the bottom of this file.
 *
 * Each profile is self‑contained, so you won’t have to edit the scenario
 * object itself—just toggle one line.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

/* ───── Runtime tunables via environment ────────────────────────────
   $ k6 run -e PACE_MS=50 zk-bench-staged.js
   VUS and DUR are no longer required because we drive load via arrival‑rate.
*/
const PACE_MS = (__ENV.PACE_MS || 100) * 1;

/* ───── Easy (smoke) profile ─────────────────────────────────────── */
const easyOptions = {
  scenarios: {
    easy: {
      executor: 'ramping-arrival-rate',
      startRate: 2,         // 2 iterations per second
      timeUnit: '1s',
      preAllocatedVUs: 20,
      stages: [
        { target: 10, duration: '2m' },  // ramp to 10 rps over 2 min
        { target: 10, duration: '1m' },  // hold
      ],
      gracefulStop: '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<350'],
  },
};

/* ───── Medium (average) profile ─────────────────────────────────── */
const mediumOptions = {
  scenarios: {
    medium: {
      executor: 'ramping-arrival-rate',
      startRate: 5,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      stages: [
        { target: 25, duration: '1m' },
        { target: 60, duration: '2m' },
        { target: 60, duration: '2m' },  // hold
      ],
      gracefulStop: '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<350'],
  },
};

/* ───── Hard (stress) profile ────────────────────────────────────── */
const hardOptions = {
  scenarios: {
    hard: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      stages: [
        { target: 60, duration: '1m' },
        { target: 100, duration: '2m' },
        { target: 150, duration: '2m' },
        { target: 150, duration: '2m' }, // hold
      ],
      gracefulStop: '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<350'],
  },
};

/* ---- Choose one profile (easy by default) ---- */
// export const options = easyOptions;
// export const options = mediumOptions;
export const options = hardOptions;

/* ───── Custom latency trends ─────────────────────────────────────── */
const regTrend = new Trend('register_latency');
const proofTrend = new Trend('proof_latency');
const verTrend = new Trend('verify_latency');

/* Helper: record latency + succeed flag, abort VU if call failed */
function postJson(url, body, trend, label) {
  const res = http.post(url, JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
  const ok = check(res, { [label]: (r) => r.status === 200 });
  if (trend) trend.add(res.timings.duration);
  return ok ? res : null; // null signals failure
}

export default function () {
  /* -------- 1. REGISTER -------- */
  const uid = `${__VU}_${Date.now()}_${Math.random()}`;
  const regBody = {
    email: `u${uid}@x.io`,
    name: uid,
    age: 30,
    country: 'US',
    dob: '1990-01-01',
  };
  const regRes = postJson(
    'http://localhost:8080/register',
    regBody,
    regTrend,
    'register 200'
  );
  if (!regRes) {
    sleep(PACE_MS / 1000);
    return;
  }

  const { secret, commitment } = regRes.json();

  /* -------- 2. PROOF -------- */
  const proofRes = postJson(
    'http://localhost:8080/proof',
    { secret_hex: secret, commitment },
    proofTrend,
    'proof 200'
  );
  if (!proofRes) {
    sleep(PACE_MS / 1000);
    return;
  }

  const { proof } = proofRes.json();

  /* -------- 3. VERIFY -------- */
  postJson(
    'http://localhost:8080/verify',
    { commitment, proof },
    verTrend,
    'verify 200'
  );

  /* pacing to avoid a tight loop */
  sleep(PACE_MS / 1000);
}
