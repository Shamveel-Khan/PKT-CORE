# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 pkt-core contributors
#
# Build / test / install helpers for the pkt_core_native accelerator.
# Run `make help` for the targets.

CARGO ?= cargo
MATURIN ?= python3 -m maturin
PIP ?= python3 -m pip
PYTEST ?= python3 -m pytest
REPO_ROOT := $(abspath $(CURDIR)/../..)

.PHONY: help test wheel install develop bench fmt clean

help:
	@echo "pkt_core_native targets:"
	@echo "  make test     - cargo test (the published KATs; --no-default-features)"
	@echo "  make wheel    - maturin build --release into ./dist"
	@echo "  make install  - build the wheel and pip install it"
	@echo "  make develop  - maturin develop (editable, needs an active venv)"
	@echo "  make bench    - benchmark Rust vs libgcrypt vs pure Python"
	@echo "  make pytest   - repo test suite with the accelerator forced"
	@echo "  make clean    - remove build artefacts"

# --no-default-features drops `extension-module`, which otherwise prevents the
# test binary from linking libpython. The wheel build keeps it enabled.
test:
	$(CARGO) test --no-default-features

wheel:
	$(MATURIN) build --release --out dist

install: wheel
	$(PIP) install --force-reinstall dist/pkt_core_native-*.whl

develop:
	$(MATURIN) develop --release

bench:
	python3 $(REPO_ROOT)/tools/bench_crypto_backends.py

pytest:
	PKT_CORE_BACKEND=rust $(PYTEST) $(REPO_ROOT)/tests

clean:
	$(CARGO) clean
	rm -rf dist
