# Builds simsvc.elf (RISC-V, CKB-VM) the same way as the C services of ckb-service-runner.
# STDLIB = path of ckb-c-stdlib, e.g. a clone of ckb-service-runner: services/c/deps/ckb-c-stdlib.
CC := clang
STDLIB ?= ../../ckb-service-runner/services/c/deps/ckb-c-stdlib

CFLAGS := --target=riscv64 -march=rv64imc_zba_zbb_zbc_zbs -O3 \
          -fdata-sections -ffunction-sections \
          -fno-builtin-printf -fno-builtin-memcmp \
          -nostdlib -Wall -Werror \
          -I$(STDLIB) -I$(STDLIB)/libc
LDFLAGS := -static $(LDEXTRA) -Wl,--gc-sections -Wl,--strip-all

simsvc.elf: simsvc.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f simsvc.elf

.PHONY: clean
