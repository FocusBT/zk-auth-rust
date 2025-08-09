#!/usr/bin/env node
/*
 * Benchmark script for Rust zk‑authentication prototype
 * ------------------------------------------------------
 * This script mirrors the NestJS benchmark used previously, but
 * targets the Rust implementation of the same API.  It exercises
 * the `/register`, `/proof` and `/verify` endpoints running on
 * localhost:8080.  Concurrency levels, durations and resource
 * monitoring are identical to the NestJS benchmark.
 */

const autocannon = require('autocannon');
const axios      = require('axios');
const pidusage   = require('pidusage');
const { exec }   = require('child_process');

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
const BASE_URL          = process.env.BASE_URL || 'http://localhost:8080';
const CONCURRENCY_LEVELS = [1, 10, 15, 20, 25, 30];   // tailor to your needs
const TEST_DURATION      = 15;            // seconds
const SAMPLE_INTERVAL_MS = 250;           // PID sampling interval

function buildUser () {
  const rnd = Math.random().toString(36).slice(2);
  return {
    email   : `user-${rnd}@example.com`,
    name    : 'Alice Doe',
    age     : 35,
    country : 'US',
    dob     : '1989-05-17'
  };
}

// -----------------------------------------------------------------------------
// Small helper utilities
// -----------------------------------------------------------------------------
function execPromise (cmd) {
  return new Promise((resolve, reject) =>
    exec(cmd, (err, stdout, stderr) =>
      err ? reject(err) : resolve({ stdout, stderr })));
}

async function waitForServer (maxAttempts = 30, delayMs = 1000) {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      await axios.get(BASE_URL).catch(e => e.response); // any HTTP resp == “up”
      return;
    } catch {
      if (i === maxAttempts)
        throw new Error(`Server not reachable at ${BASE_URL}`);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

async function findServerPid () {
  try {
    const url  = new URL(BASE_URL);
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    const { stdout } = await execPromise(`lsof -i :${port} -t | head -n1`);
    const pid = parseInt(stdout.trim(), 10);
    return Number.isNaN(pid) ? null : pid;
  } catch { return null; }
}

function startResourceMonitor (pid) {
  const samples = [];
  const timer   = setInterval(async () => {
    try { samples.push(await pidusage(pid)); } catch {}
  }, SAMPLE_INTERVAL_MS);

  return { stop () { clearInterval(timer); }, samples };
}

function computeAverages (samples) {
  if (!samples.length) return null;
  const sum = samples.reduce((a, s) =>
    ({ cpu: a.cpu + s.cpu, memory: a.memory + s.memory }),
    { cpu: 0, memory: 0 });
  const n = samples.length;
  return { cpu: sum.cpu / n, memory: sum.memory / n };
}

function runAutocannon (opts) {
  return new Promise((res, rej) => {
    const inst = autocannon({ url: BASE_URL, ...opts }, (e, r) => e ? rej(e) : res(r));
    autocannon.track(inst, { renderProgressBar: false });
  });
}

// -----------------------------------------------------------------------------
// Main workflow
// -----------------------------------------------------------------------------
(async function main () {
  console.log(`Waiting for ${BASE_URL} …`);
  await waitForServer();
  console.log('Server is up, pre‑computing proof/verification payloads …');

  // --- pre‑compute secret / proof so they’re valid for all tests ----
  let secretHex, commitment, proof;
  try {
    const reg = await axios.post(`${BASE_URL}/register`, buildUser());
    secretHex  = reg.data.secret;
    commitment = reg.data.commitment;

    const prf = await axios.post(`${BASE_URL}/proof`, { secret_hex: secretHex, commitment });
    proof = prf.data.proof;

    const verResp = await axios.post(`${BASE_URL}/verify`, { commitment, proof });
    if (!verResp.data.valid) {
      throw new Error('Initial verification failed; proof or commitment invalid');
    }
  } catch (e) {
    console.error('❌  Failed to pre‑compute proof / verification payloads');
    throw e;
  }

  // ----------------------- define endpoint benchmarks ------------------------
  const endpoints = [
    {
      name     : 'register',
      requests : [{
        method : 'POST',
        path   : '/register',
        headers: { 'Content-Type': 'application/json' },
        setupRequest (req /*, ctx */) {
          req.body = JSON.stringify(buildUser());
          return req;
        }
      }]
    },
    {
      name     : 'generateProof',
      requests : [{
        method : 'POST',
        path   : '/proof',
        headers: { 'Content-Type': 'application/json' },
        body   : JSON.stringify({ secret_hex: secretHex, commitment })
      }]
    },
    {
      name     : 'verifyProof',
      requests : [{
        method : 'POST',
        path   : '/verify',
        headers: { 'Content-Type': 'application/json' },
        body   : JSON.stringify({ commitment, proof })
      }]
    }
  ];

  // --------------------------- run all benchmarks ---------------------------
  const serverPid = await findServerPid();
  if (serverPid)
    console.log(`Monitoring server PID ${serverPid} for CPU/memory …`);
  else
    console.warn('Server PID not found – CPU/memory stats will be “n/a”.');

  const summaries = [];

  for (const ep of endpoints) {
    console.log(`\n▶  Endpoint: ${ep.name}`);
    for (const c of CONCURRENCY_LEVELS) {
      console.log(`   – concurrency ${c} for ${TEST_DURATION}s`);
      const monitor = serverPid ? startResourceMonitor(serverPid) : null;

      const result = await runAutocannon({
        connections: c,
        duration   : TEST_DURATION,
        requests   : ep.requests
      });

      if (monitor) monitor.stop();
      const avg = monitor ? computeAverages(monitor.samples) : null;

      summaries.push({
        endpoint      : ep.name,
        concurrency   : c,
        latencyAvg    : result.latency.average,
        latencyP50    : result.latency.p50 || result.latency.median || result.latency.mean,
        throughputAvg : result.throughput.average,
        requestsPerSec: result.requests.average,
        cpu           : avg ? avg.cpu    : null,
        memory        : avg ? avg.memory : null
      });
    }
  }

  // ------------------------------- print table ------------------------------
  console.log('\n====================== Benchmark results ======================');
  for (const s of summaries) {
    console.log(`\n${s.endpoint}  (concurrency ${s.concurrency})`);
    console.log('  Avg latency  :', s.latencyAvg.toFixed(2), 'ms');
    console.log('  P50 latency  :', s.latencyP50.toFixed(2), 'ms');
    console.log('  Throughput   :', (s.throughputAvg / 1024 / 1024).toFixed(2), 'MB/s');
    console.log('  Requests/sec :', s.requestsPerSec.toFixed(2));
    if (s.cpu !== null) {
      console.log('  CPU (avg)    :', s.cpu.toFixed(2), '%');
      console.log('  Memory (avg) :', (s.memory / 1024 / 1024).toFixed(2), 'MB');
    } else {
      console.log('  CPU/memory   : n/a');
    }
  }
  console.log('\nBenchmark completed ✅');
})().catch(err => { console.error(err); process.exit(1); });