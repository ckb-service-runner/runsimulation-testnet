/*
 * simsvc: the CSR test service of runsimulation-testnet.
 *
 * One small RISC-V program that the simulator's jobs name in their job type args (its data hash).
 * The job payload selects what it does:
 *
 *   [optional 41-byte watch header "CSRW" 01 <out point>]   (CSR OnCellConsumed convention)
 *   "CSRS" | 0x01 | mode (1) | nonce (8) | assigned runner lock hash (32, zero = any) | mode args
 *
 *   mode 1 OK        increments a counter in the service storage, result "SIMOK" nonce counter
 *   mode 2 FAIL      exits 42: the run fails, the job must never settle (tests failure + refund)
 *   mode 3 CRT_REL   args = switch out point (36): live -> result "CRTREL" nonce, dead (revoked) -> exit 43
 *   mode 4 CRT_CLEAN watch job on the switch: runs after it was consumed, result "CRTCLN" nonce
 *   mode 5 CROWD     args = CrowdCell campaign out point (36): reads the campaign cell and returns
 *                    "CCELL" status, verdict (total >= goal), goal, total, deadline; dead -> exit 45
 *
 * Other exit codes: 40 bad payload, 41 storage error, 44/46 node read failed (46 = local mode, no node).
 * Host interface: ckb-service-runner spec/host-interface.md.
 */
#include "ckb_syscalls.h"

#define CSR_JOB_PAYLOAD 7001
#define CSR_BLOCK_INFO 7002
#define CSR_CHAIN_READ 7003
#define CSR_KV_GET 7010
#define CSR_KV_PUT 7011
#define CSR_RESULT_PUT 7031

#define HDR_LEN 46 /* "CSRS" 4 + version 1 + mode 1 + nonce 8 + assigned 32 */
#define WATCH_LEN 41

static uint8_t payload[512];
static uint8_t out[128];
static uint8_t cell[256];

static int put_result(const uint8_t *tag, uint64_t tag_len, const uint8_t *nonce, const uint8_t *extra,
                      uint64_t extra_len) {
  uint64_t n = 0;
  memcpy(out, tag, tag_len);
  n += tag_len;
  memcpy(out + n, nonce, 8);
  n += 8;
  if (extra_len) {
    memcpy(out + n, extra, extra_len);
    n += extra_len;
  }
  return syscall(CSR_RESULT_PUT, out, n, 0, 0, 0, 0) == 0 ? 0 : 41;
}

/* chain_read kind 0 (cell output) or 1 (cell data). 0 live, 1 dead/unknown, 2 local mode, else error. */
static int read_cell(uint64_t kind, const uint8_t *outpoint, uint8_t *buf, uint64_t *len) {
  return (int)syscall(CSR_CHAIN_READ, kind, outpoint, buf, len, 0, 0);
}

int main(void) {
  uint64_t len = sizeof(payload);
  if (syscall(CSR_JOB_PAYLOAD, payload, &len, 0, 0, 0, 0) != 0) return 40;
  if (len > sizeof(payload)) return 40;
  uint8_t *p = payload;
  if (len >= WATCH_LEN && memcmp(p, "CSRW", 4) == 0) {
    p += WATCH_LEN;
    len -= WATCH_LEN;
  }
  if (len < HDR_LEN || memcmp(p, "CSRS", 4) != 0 || p[4] != 1) return 40;
  uint8_t mode = p[5];
  const uint8_t *nonce = p + 6;
  const uint8_t *args = p + HDR_LEN;
  uint64_t args_len = len - HDR_LEN;

  if (mode == 1) {
    uint8_t buf[4];
    uint64_t blen = 4;
    uint32_t c = 0;
    int r = (int)syscall(CSR_KV_GET, "counter", 7, buf, &blen, 0, 0);
    if (r == 0 && blen == 4) {
      memcpy(&c, buf, 4);
    } else if (r != 1) {
      return 41;
    }
    c += 1;
    memcpy(buf, &c, 4);
    if (syscall(CSR_KV_PUT, "counter", 7, buf, 4, 0, 0) != 0) return 41;
    return put_result((const uint8_t *)"SIMOK", 5, nonce, buf, 4);
  }
  if (mode == 2) return 42;
  if (mode == 3) {
    if (args_len < 36) return 40;
    uint64_t clen = sizeof(cell);
    int r = read_cell(0, args, cell, &clen);
    if (r == 1) return 43; /* switch consumed: revoked, never release */
    if (r == 2) return 46;
    if (r != 0) return 44;
    return put_result((const uint8_t *)"CRTREL", 6, nonce, 0, 0);
  }
  if (mode == 4) return put_result((const uint8_t *)"CRTCLN", 6, nonce, 0, 0);
  if (mode == 5) {
    if (args_len < 36) return 40;
    uint64_t clen = sizeof(cell);
    int r = read_cell(1, args, cell, &clen);
    if (r == 1) return 45;
    if (r == 2) return 46;
    if (r != 0) return 44;
    if (clen < 57) return 40;
    uint64_t goal, deadline, total;
    memcpy(&goal, cell + 32, 8);
    memcpy(&deadline, cell + 40, 8);
    memcpy(&total, cell + 48, 8);
    uint8_t extra[26];
    extra[0] = cell[56];             /* status: 0 active, 1 success, 2 failed */
    extra[1] = total >= goal ? 1 : 0; /* verdict at the time of the run */
    memcpy(extra + 2, &goal, 8);
    memcpy(extra + 10, &total, 8);
    memcpy(extra + 18, &deadline, 8);
    return put_result((const uint8_t *)"CCELL", 5, nonce, extra, sizeof(extra));
  }
  return 40;
}
