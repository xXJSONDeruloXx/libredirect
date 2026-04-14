# libredirect build — cross-compiles for aarch64
#
# Prerequisites:
#   GLIBC version:  aarch64-linux-gnu-gcc (apt: gcc-aarch64-linux-gnu)
#   Bionic version: Android NDK (set NDK_HOME or ANDROID_NDK_HOME)
#
# Usage:
#   make                     # build both (uses defaults)
#   make OLD_SUB=com.foo NEW_SUB=app.bar   # custom package IDs
#   make bionic              # bionic only
#   make glibc               # glibc only
#   make clean

# --- Package identity (override on command line) ---
OLD_SUB      ?= com.winlator
NEW_SUB      ?= app.gnlime
OLD_SUB_LONG ?= $(OLD_SUB)/files/rootfs
NEW_SUB_LONG ?= $(NEW_SUB)/files/imagefs

DATA_PREFIX  ?= /data/data/$(NEW_SUB)/files/imagefs

GOLDBERG_PRELOAD ?= LD_PRELOAD=$(DATA_PREFIX)/libpluviagoldberg.so

# --- Toolchains ---
CROSS_GCC    ?= aarch64-linux-gnu-gcc
NDK_HOME     ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK))
NDK_CLANG    ?= $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
NDK_API      ?= 35

# --- Flags ---
COMMON_DEFS  = \
	-DOLD_SUB='"$(OLD_SUB)"' \
	-DNEW_SUB='"$(NEW_SUB)"' \
	-DOLD_SUB_LONG='"$(OLD_SUB_LONG)"' \
	-DNEW_SUB_LONG='"$(NEW_SUB_LONG)"'

GLIBC_CFLAGS  = -shared -fPIC -O2 -Wall -Wno-unused-function \
	$(COMMON_DEFS) \
	-DGOLDBERG_PRELOAD='"$(GOLDBERG_PRELOAD)"' \
	-DTMP_REDIRECT='"$(DATA_PREFIX)/usr/tmp"' \
	-DPRELOAD_MARKER='"$(DATA_PREFIX)/preload_loaded.txt"'

BIONIC_CFLAGS = -shared -fPIC -O2 -Wall -DNDEBUG \
	-DOLD_PKG='"$(OLD_SUB)"' \
	-DNEW_PKG='"$(NEW_SUB)"'

# Note: bionic version uses OLD_PKG/NEW_PKG (short form only)
# because the bionic side only rewrites "com.winlator.cmod" → pkg

# --- Outputs ---
OUT_DIR      ?= out
GLIBC_SO     = $(OUT_DIR)/libredirect.so
BIONIC_SO    = $(OUT_DIR)/libredirect-bionic.so

# --- Targets ---
.PHONY: all glibc bionic clean docker-build

all: glibc bionic

glibc: $(GLIBC_SO)

bionic: $(BIONIC_SO)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(GLIBC_SO): preload_replace.c | $(OUT_DIR)
	$(CROSS_GCC) $(GLIBC_CFLAGS) -o $@ $< -ldl

$(BIONIC_SO): preload_replace_bionic.c | $(OUT_DIR)
	$(NDK_CLANG) $(BIONIC_CFLAGS) -o $@ $< -ldl

clean:
	rm -rf $(OUT_DIR)

# --- Docker-based build (no local cross-compiler needed) ---
docker-build:
	docker run --rm -v "$(CURDIR):/src" -w /src ubuntu:22.04 bash -c '\
		apt-get update -qq && \
		apt-get install -y -qq gcc-aarch64-linux-gnu >/dev/null 2>&1 && \
		make glibc CROSS_GCC=aarch64-linux-gnu-gcc'
	@echo "GLIBC build complete: $(GLIBC_SO)"
	@echo "Note: bionic build requires Android NDK — use 'make bionic' with NDK_HOME set"
