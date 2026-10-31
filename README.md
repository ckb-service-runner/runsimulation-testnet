# runsimulation-testnet

A small, always-on **job simulator for the [CKB Service Runner](https://github.com/ckb-service-runner/ckb-service-runner) (CSR) network on the CKB testnet**.

It plays the *customer* side of CSR: it posts real CSR job cells at random times, any registered CSR runner can execute them, and it checks on chain that everything happened the way the contracts promise: who ran what, whether the tip arrived, whether failing jobs were left alone, and that unrun jobs come back as refunds. It does not run a CSR node and does not execute jobs itself.

If you operate a CSR runner on testnet, this gives your node real work and real tips to show on its dashboard. See [Take part as a runner](#take-part-as-a-runner).

## What it exercises

Every job is a real `csr-job-type` + `csr-job-lock` cell of the deployed CSR contracts (v3), paid for by the simulator. The job cell *is* the escrow: its CKB can only leave as tip-plus-change to a registered runner on a valid run, or back to the simulator after expiry.

| Kind | Job | Expected outcome | CSR part under test |
|---|---|---|---|
| `ok` | on demand, service succeeds | settled by a runner | discovery, sandbox, storage, tip settlement |
| `timed` | `AtBlock(n)` | settled at or after block n, never before | `since`-proven triggers |
| `every` | `Every(k)`, 3 runs | 3 settlements, job recreated in between | recurring jobs, recreation at the job index |
| `fail` | service exits with an error | **never** settled, refunded after expiry | failed runs, retry limit, refund path |
| `crt` | [CKB Revocable Timelock](https://github.com/psawyerberlin/ckb-revocable-timelock) pattern: a switch cell, a release job at block T that only succeeds while the switch is live, a cleanup job that watches the switch | revoked switch: release refunded, cleanup settled. Live switch: release settled, then the switch is reclaimed and cleanup settles | node reads (`chain_read`), the `OnCellConsumed` watch convention |
| `crowdcell` | reads a live [CrowdCell](https://github.com/alesfer001/CrowdCell) campaign cell on testnet (at its deadline when it is close) and returns status, goal, total and verdict | settled while the campaign cell is live | node reads of a third-party app's cells |

A share of the jobs is **addressed to one registered runner** (`assign_fraction`). CSR has no on-chain assignment yet, so this is soft: the target is written into the payload and the simulator reports whether that runner or another one served it (`assigned_served_by_target` / `assigned_served_by_other`). Enforcing it would need a small CSR change (a runner-side rule or an optional runner lock hash in the job), which this data helps decide.

**Verification.** For every settlement the simulator checks: the runner wallet output grew by at least the tip; the recreated job (or the refund to the simulator) sits at the job input's index with at least capacity − tip − max fee; the run was not before its trigger block; a `fail` job never settled; a CRT release did not settle after its switch was revoked. Anything else is logged as `ANOMALY` and kept in the state file.

Honest limits: CRT has no code yet, so `crt` simulates its on-chain pattern with the simulator's own switch cells, not CRT's key handling. `crowdcell` reads CrowdCell cells but does not finalize campaigns (CrowdCell's own bot does that).

## How it is built

- `sim.py`: one Python file, **standard library only** (Python 3.8+). It carries its own secp256k1 signing, molecule encoding and address code, and talks JSON-RPC to a testnet node with the Indexer module (default `https://testnet.ckb.dev/rpc`).
- `service/simsvc.elf`: the 2.6 KB RISC-V test service (source `simsvc.c`), published once as a code cell by the simulator.
- A systemd **timer** runs `sim.py tick` every 10 minutes: nothing stays resident. A tick costs a few RPC calls and well under a second of CPU; state is one small JSON file plus a size-capped event log.
- No database, no container, no web server, no dashboard. `sim.py status` prints everything as JSON.

## Money rules

- **Hard cap:** `monthly_cap_ckb` (100,000). Every CKB placed into a job cell, a switch cell or the service code cell counts toward the month; refunds coming back do not reset it. So the simulator can never distribute or lock more than the cap in a calendar month (UTC). Tips and fees, the CKB that really leaves, are a few hundred CKB a month at the defaults.
- **Pacing** spreads the cap over the month, so a busy first day cannot use it all.
- **Reserve:** no job is created that would leave the wallet below `reserve_ckb`.
- **Funding:** with `faucet = auto` the simulator asks the [testnet faucet](https://faucet.nervos.org/) for 100,000 CKB at most once a month, and only while its balance is below `faucet_below_ckb`. It uses the faucet's public claim endpoint, the one its web form posts to; the faucet allows 300,000 CKB per address and month. If the claim is refused, or with `faucet = manual`, it logs `funding_needed` with the address: send testnet CKB there from any wallet.

## Install (Linux, systemd)

```sh
git clone https://github.com/ckb-service-runner/runsimulation-testnet
cd runsimulation-testnet
sudo bash deploy/install.sh            # user runsim, /opt/runsim, /etc/runsim/runsim.ini, prints the address
# fund the address, or let the faucet do it:
sudo -u runsim python3 /opt/runsim/sim.py --config /etc/runsim/runsim.ini faucet
sudo -u runsim python3 /opt/runsim/sim.py --config /etc/runsim/runsim.ini deploy-service
sudo systemctl enable --now runsim.timer
sudo -u runsim python3 /opt/runsim/sim.py --config /etc/runsim/runsim.ini status
```

`tick --dry-run` checks the transactions of one tick with the node's `test_tx_pool_accept` and changes nothing; `tick --create KIND` creates a job of that kind now. Logs: `journalctl -u runsim` and `/var/lib/runsim/events.jsonl`. Keep `/var/lib/runsim/sim.key` (testnet only, but it owns the open jobs).

Configuration: `deploy/runsim.ini.example` (every key optional).

## Take part as a runner

On a CSR runner (v0.4.x, registered on testnet, `runtime.enabled = true`):

```sh
csr service add-onchain --outpoint <SERVICE OUTPOINT>
csr service approve <SERVICE CODE HASH>
```

or approve it on the dashboard's Services page. Approving adds the code hash to `runtime.allowed_services`.

| | |
|---|---|
| Service code hash | `0xbe86725b9c2df8538871ac68e500686766cb49ae38c539ba1e3d7ad0f0f9c1b3` |
| Service code cell (testnet) | `<SERVICE OUTPOINT>` (published by the simulator's `deploy-service`) |

The code hash is the blake2b data hash of `service/simsvc.elf`; rebuild it with `make -C service` (clang with the RISC-V target, ckb-c-stdlib from the CSR repository) and compare. The service has no network, no file access and no key: it reads the job payload, keeps one counter in its sandbox storage and reads the cells named in the payload.

## Tests

- `python3 sim.py selftest`: offline (secp256k1 vectors, addresses, job encoding).
- `test/devnet-e2e.mjs`: the full loop on a local CKB devnet with a real, registered CSR runner: every job kind, settlement, failure, refund, CRT revocation and release, budget ledger, runner wallet = tips seen. Run it from a `ckb-service-runner` checkout (instructions at the top of the file).

## License

MIT
