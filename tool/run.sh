#!/usr/bin/env bash
# =============================================================================
#  InflationGuard - full pipeline in one command.
#
#    DETECT  ->  SYNTHESIZE  ->  PROVE  ->  MUTATE
#
#  1. Reproduce the exploit (and show the fix blocks it)
#  2. Static detection (Semgrep + Slither) flags the vulnerable code only
#  3. Synthesize the invariant suite from the finding
#  4. Prove the invariant PASSES on the fix and FAILS on the historic bug
#  5. Mutation gate: re-introduce the bug; show happy-path tests are blind and
#     InflationGuard's artifacts catch it
#
#  Usage:  bash tool/run.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

bold=$'\033[1m'; cyn=$'\033[96m'; grn=$'\033[92m'; red=$'\033[91m'; dim=$'\033[2m'; rst=$'\033[0m'
step() { echo; echo "${cyn}${bold}━━━ $* ━━━${rst}"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Resolve the python that can import slither (its CLI is often venv-isolated).
slither_python() {
  if python3 -c "import slither" 2>/dev/null; then echo "python3"; return; fi
  if have slither; then
    local interp; interp="$(head -1 "$(command -v slither)" | sed 's/^#!//')"
    if [ -x "$interp" ] && "$interp" -c "import slither" 2>/dev/null; then echo "$interp"; return; fi
  fi
  echo ""
}

FAIL=0

step "1/5  EXPLOIT  -  reproduce zkLend/Resupply/ERC-4626, prove the fix blocks it"
forge test --match-contract ExploitTest -vv || FAIL=1

step "2/5  DETECT  -  static analysis flags the vulnerable code (zero FP on the fix)"
if have semgrep; then
  echo "${dim}» Semgrep ruleset${rst}"
  semgrep --quiet --config tool/inflationguard/semgrep/inflationguard.yml src/ || true
else
  echo "${dim}(semgrep not installed - skipping; pip install semgrep)${rst}"
fi
SPY="$(slither_python)"
if [ -n "$SPY" ]; then
  echo "${dim}» Slither semantic detector${rst}"
  "$SPY" tool/inflationguard/inflationguard_slither.py . 2>/dev/null
  echo "${dim}(exit = HIGH-severity finding count)${rst}"
else
  echo "${dim}(slither not importable - skipping; pip install slither-analyzer)${rst}"
fi

step "3/5  SYNTHESIZE  -  generate the invariant suite from the finding"
# real Detect -> Synthesize wiring: feed the detector's JSON finding in.
# (the --json detector exits with the HIGH-finding count, so ignore its status.)
FINDINGS=/tmp/inflationguard-findings.json
if [ -n "$SPY" ] && "$SPY" tool/inflationguard/inflationguard_slither.py . --json > "$FINDINGS" 2>/dev/null; then :; fi
if [ -n "$SPY" ] && [ -s "$FINDINGS" ]; then
  python3 tool/inflationguard/synthesize_invariant.py --from-finding "$FINDINGS" || FAIL=1
else
  python3 tool/inflationguard/synthesize_invariant.py || FAIL=1
fi

# A fixed seed + a clean invariant cache make the PROVE/MUTATE stages reproducible
# (a stale cached counterexample must never replay as a phantom failure).
SEED=0x0177a7104f1a710
rm -rf cache/invariant 2>/dev/null

step "4/5  PROVE  -  invariant PASSES on the fix, FAILS on the historic bug"
echo "${dim}» against the hardened contract (expect PASS):${rst}"
forge test --match-contract InflationGuardVaultInvariant --fuzz-seed "$SEED" || FAIL=1
echo "${dim}» against the historic buggy contract (expect FAIL - the invariant catches it):${rst}"
rm -rf cache/invariant 2>/dev/null
if GUARD_TARGET=vulnerable forge test --match-contract InflationGuardVaultInvariant --fuzz-seed "$SEED" >/dev/null 2>&1; then
  echo "${red}UNEXPECTED: invariant passed on the vulnerable contract${rst}"; FAIL=1
else
  echo "${grn}✓ invariant correctly FAILED on the vulnerable contract${rst}"
fi

step "5/5  MUTATE  -  re-introduce the bug; who notices?"
python3 tool/mutation/mutate.py || FAIL=1

echo
if [ "$FAIL" -eq 0 ]; then
  echo "${grn}${bold}✓ InflationGuard pipeline complete.${rst}"
else
  echo "${red}${bold}✗ pipeline reported a problem (see above).${rst}"
fi
exit "$FAIL"
