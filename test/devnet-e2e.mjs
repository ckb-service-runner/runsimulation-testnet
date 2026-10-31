// End-to-end test of the simulator against a real CSR runner on a local CKB devnet.
//
// Run from a ckb-service-runner checkout (it provides the devnet harness, csr and csr-dev):
//   cargo build -p csr -p csr-dev && bash scripts/build-contracts.sh
//   bash scripts/devnet.sh reset && bash scripts/devnet.sh start
//   SIM_DIR=/path/to/runsimulation-testnet node --test --test-concurrency=1 $SIM_DIR/test/devnet-e2e.mjs
//
// One registered runner with the simulation service approved; the simulator creates one job of every
// kind; blocks are mined until every job has ended. Checks: the right jobs settle (tip in the runner
// wallet), failing / revoked ones are refunded to the simulator, no anomaly, the budget ledger is kept.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();
const SIM_DIR = process.env.SIM_DIR || path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const A = (p) => path.join(ROOT, 'acceptance', p);
const { cleanup, startCsr, getJson, waitFor, runCsr } = await import(A('a1/lib.mjs'));
const { startMiner } = await import(A('a3c/jobs.mjs'));
const { deploy, deposit } = await import(A('a7/flow.mjs'));
const { runner, fundRunnerCell, registerWithConsent, wallet } = await import(A('a8/flow.mjs'));
const { csrDev, waitCommitted, DEPLOYMENTS } = await import(A('a3b/devnet.mjs'));

after(cleanup);

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runsim-e2e-'));
const ini = path.join(dataDir, 'runsim.ini');
fs.writeFileSync(ini, `[sim]
rpc_url = http://127.0.0.1:18114
data_dir = ${dataDir}
deployments = ${DEPLOYMENTS}
service_elf = ${path.join(SIM_DIR, 'service', 'simsvc.elf')}
faucet = off
monthly_cap_ckb = 100000
reserve_ckb = 500
expiry_blocks = 60
delay_max_blocks = 40
assign_fraction = 0.5
tick_minutes = 0
pacing = off
`);

function sim(...args) {
  const out = execFileSync('python3', [path.join(SIM_DIR, 'sim.py'), '--config', ini, ...args], { encoding: 'utf8' });
  return out;
}
const status = () => JSON.parse(sim('status'));

test('simulator: every job kind against a registered runner', { timeout: 900000 }, async () => {
  const dep = await deploy();
  const r = await runner('runsim-e2e', undefined, (c) => { c.runtime.enabled = true; return c; });
  await fundRunnerCell(r, 700);
  await registerWithConsent(r, await deposit(10000));

  const addr = JSON.parse(sim('init'));
  const lockArgs = '0x' + execFileSync('python3', ['-c',
    `import sys;sys.path.insert(0,${JSON.stringify(SIM_DIR)});import sim;print(sim.decode_address(${JSON.stringify(addr.address)})['args'][2:])`],
  { encoding: 'utf8' }).trim();
  const f = await csrDev(['fund', '--lock-args', lockArgs, '--ckb', '60000']);
  assert.equal(f.code, 0, f.stderr);
  await waitCommitted(f.json.tx_hash);

  const svc = JSON.parse(sim('deploy-service'));
  await waitCommitted(svc.tx_hash);
  const add = await runCsr([...r.args, 'service', 'add-onchain', '--outpoint', `${svc.tx_hash}:0`], { timeoutMs: 60000 });
  assert.equal(add.code, 0, add.stderr);
  assert.equal(JSON.parse(add.stdout).code_hash, svc.code_hash);
  const ap = await runCsr([...r.args, 'service', 'approve', svc.code_hash]);
  assert.equal(ap.code, 0, ap.stderr);

  const before = (await wallet(r)).capacity_shannons;
  await startCsr([...r.args, 'run'], { healthUrl: `${r.base}/healthz` });
  const stopMiner = startMiner(1000);
  try {
    // two CRT switches so that both the revoked and the released path are likely; one of each other kind
    for (const kind of ['ok', 'timed', 'every', 'fail', 'crt', 'crt', 'crt']) {
      sim('tick', '--create', kind);
    }
    const ended = await waitFor(async () => {
      sim('tick');
      const s = status();
      const open = (s.jobs_by_state.open || 0) + (s.jobs_by_state.refunding || 0);
      return open === 0 && s.pending_txs === 0 && s;
    }, 800000, 3000);
    const s = ended;
    console.log(JSON.stringify(s, null, 1));
    assert.deepEqual(s.anomalies, [], 'no anomaly');
    assert.equal(s.stats.anomalies, undefined);
    assert.equal(s.stats.settled_ok, 1);
    assert.equal(s.stats.settled_timed, 1);
    assert.equal(s.stats.settled_every, 3, 'every: three runs');
    assert.equal(s.stats.settled_fail, undefined, 'a failing job never settles');
    const crt = JSON.parse(fs.readFileSync(path.join(dataDir, 'state.json'), 'utf8'));
    const rel = Object.values(crt.jobs).filter((j) => j.kind === 'crt');
    const clean = Object.values(crt.jobs).filter((j) => j.kind === 'crt_cleanup');
    assert.equal(rel.length, 3);
    for (const j of rel) {
      const sw = crt.switches[j.switch];
      if (sw.consumed_block !== undefined && sw.consumed_block < j.tvalue) {
        assert.equal(j.state, 'refunded', `release job ${j.id}: switch revoked at ${sw.consumed_block} before ${j.tvalue}`);
      } else {
        assert.equal(j.state, 'settled', `release job ${j.id} of a live switch settles`);
      }
    }
    assert.ok(rel.some((j) => j.revoke && j.state === 'refunded') || rel.every((j) => !j.revoke),
      'a revoked switch blocks its release');
    for (const j of clean) assert.equal(j.state, 'settled', `cleanup ${j.id} runs after the switch is consumed`);
    const fail = Object.values(crt.jobs).filter((j) => j.kind === 'fail');
    assert.equal(fail[0].state, 'refunded');
    // the runner wallet grew by exactly the tips the simulator saw
    const tips = Object.values(crt.runners_seen).reduce((a, x) => a + x.tips * 1e8, 0);
    const after1 = (await wallet(r)).capacity_shannons;
    assert.equal(after1 - before, Math.round(tips));
    assert.ok(s.month.committed > 0 && s.month.committed <= 100000);
    void dep;
  } finally {
    await stopMiner();
  }
});
