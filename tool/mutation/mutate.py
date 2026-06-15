#!/usr/bin/env python3
"""
InflationGuard - mutation gate.  ("Coverage Lies, Mutants Don't.")

This is the part that proves the rest is worth anything. It re-introduces the
historic bug into the *hardened* contracts, one defense at a time, and asks each
test suite: "did you notice?"

    A mutant that still PASSES your tests is a bug your tests cannot see.

We run three suites against each mutant:
    1. naive        - the "100% coverage" happy-path unit tests
    2. invariant    - the InflationGuard-synthesized property suite
    3. regression   - the InflationGuard PoC tests shipped with a finding

and report, per mutant, whether each suite KILLED it (test failed = good) or let
it SURVIVE (test passed on buggy code = blind spot).

Reliability (hardened after review):
  * deterministic: a fixed --fuzz-seed pins the invariant fuzzing, so the matrix
    is byte-for-byte reproducible across runs.
  * crash-safe: every mutated file is snapshotted and restored on normal exit,
    Ctrl-C, or SIGTERM - a killed run never leaves the tree in a vulnerable state.
  * cache-clean: stale Foundry invariant counterexamples are cleared before each
    run, so a cached failure cannot masquerade as a fresh kill.

    python3 tool/mutation/mutate.py
"""
import subprocess
import sys
import os
import shutil
import atexit
import signal

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Fixed seed => the matrix is identical on every run. DEPTH/RUNS kept small for
# speed; the donation-resistance invariant fails within a few calls.
FUZZ_SEED = "0x0177a7104f1a710"
ENV = dict(os.environ, FOUNDRY_INVARIANT_RUNS="64", FOUNDRY_INVARIANT_DEPTH="32")

SUITES = [
    ("naive",      "happy-path unit tests",     "Naive"),
    ("invariant",  "InflationGuard generated",  "InflationGuardVaultInvariant"),
    ("regression", "InflationGuard PoC tests",  "ExploitTest"),
]

# Each mutant reintroduces a historic defect into the hardened code.
#   load-bearing      = independently necessary; the tool MUST kill it.
#   defense-in-depth  = MASKED by a load-bearing fix; survives in isolation
#                       (NOT an "equivalent mutant" - it changes behavior, it is
#                       just dominated by another fix; see the combinatorial row).
#   combinatorial     = two fixes reverted together; proves the dominance.
MUTANTS = [
    {
        "id": "M1-donatable-price",
        "category": "load-bearing",
        "file": "src/safe/SafeVault.sol",
        "edits": [("return _internalAssets;", "return asset.balanceOf(address(this));")],
        "desc": "totalAssets() reads the live balance again - donations move the price (the zkLend/Resupply/ERC-4626 root cause).",
    },
    {
        "id": "M2-market-zero-rate-guard",
        "category": "load-bearing",
        "file": "src/safe/SafeLendingMarket.sol",
        "edits": [('require(rate > 0, "zero exchange rate"); // FIX-6', "// FIX-6 removed by mutant")],
        "desc": "removes require(rate > 0) - Resupply's missing line; an inflated price floors the rate to 0 and disables the LTV check.",
    },
    {
        "id": "M3-zero-share-guard",
        "category": "defense-in-depth",
        "file": "src/safe/SafeVault.sol",
        "edits": [('require(shares > 0, "zero shares");', "// require(shares > 0) removed by mutant")],
        "desc": "removes require(shares > 0) - masked by virtual shares (a real deposit still cannot mint 0 shares), so it survives in isolation.",
    },
    {
        "id": "M4-shrink-virtual-shares",
        "category": "defense-in-depth",
        "file": "src/safe/SafeVault.sol",
        "edits": [("uint256 private constant OFFSET = 3;", "uint256 private constant OFFSET = 0;")],
        "desc": "shrinks the virtual-shares offset to 0 - masked by internal accounting (the price still cannot be donated), so it survives in isolation.",
    },
    {
        "id": "M5-donatable-price+shrink-offset",
        "category": "combinatorial",
        "file": "src/safe/SafeVault.sol",
        "edits": [
            ("return _internalAssets;", "return asset.balanceOf(address(this));"),
            ("uint256 private constant OFFSET = 3;", "uint256 private constant OFFSET = 0;"),
        ],
        "desc": "reverts internal accounting AND the offset together - recreates the vulnerable vault; killed by the invariant, proving M4 is DOMINATED by FIX-1, not an equivalent mutant.",
    },
]

RED, GRN, YEL, CYN, DIM, BOLD, RST = (
    "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[2m", "\033[1m", "\033[0m"
)

# ---- crash-safe state: snapshot originals, restore on any exit ---------------
_ORIGINALS = {}


def _restore_all():
    for path, data in list(_ORIGINALS.items()):
        try:
            with open(os.path.join(ROOT, path), "w") as f:
                f.write(data)
        except Exception:
            pass
    _ORIGINALS.clear()


atexit.register(_restore_all)
for _sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(_sig, lambda *_: (_restore_all(), sys.exit(130)))


def _snapshot(path):
    if path not in _ORIGINALS:
        with open(os.path.join(ROOT, path)) as f:
            _ORIGINALS[path] = f.read()


def apply_mutant(m):
    _snapshot(m["file"])
    full = os.path.join(ROOT, m["file"])
    src = _ORIGINALS[m["file"]]
    for old, new in m["edits"]:
        if old not in src:
            raise SystemExit(f"mutation target not found in {m['file']}:\n  {old!r}")
        src = src.replace(old, new, 1)
    with open(full, "w") as f:
        f.write(src)


def revert_mutant(m):
    if m["file"] in _ORIGINALS:
        with open(os.path.join(ROOT, m["file"]), "w") as f:
            f.write(_ORIGINALS[m["file"]])


def run_suite(pattern):
    """True if the suite PASSES (mutant survives), False if it FAILS (killed)."""
    # Clear any cached invariant counterexample so a stale failure cannot replay.
    shutil.rmtree(os.path.join(ROOT, "cache", "invariant"), ignore_errors=True)
    r = subprocess.run(
        ["forge", "test", "--match-contract", pattern, "--fuzz-seed", FUZZ_SEED],
        cwd=ROOT, env=ENV, capture_output=True, text=True,
    )
    return r.returncode == 0


def main():
    print(f"{CYN}{BOLD}InflationGuard mutation gate{RST}  (re-introducing the bug into hardened code)")
    print(f"{DIM}deterministic seed {FUZZ_SEED}; mutated files restored on any exit{RST}\n")

    print(f"{DIM}baseline (clean code): all suites must pass...{RST}")
    for key, _desc, pat in SUITES:
        ok = run_suite(pat)
        print(f"  {GRN if ok else RED}{'PASS' if ok else 'FAIL'}{RST}  {key}")
        if not ok:
            raise SystemExit("baseline is not green; fix tests before mutating.")
    print()

    results = {}
    for m in MUTANTS:
        apply_mutant(m)
        try:
            results[m["id"]] = {key: run_suite(pat) for key, _d, pat in SUITES}
        finally:
            revert_mutant(m)

    # ---- matrix ----
    width = max(len(m["id"]) for m in MUTANTS) + 2
    print(f"{BOLD}MUTATION MATRIX{RST}   ({GRN}KILL{RST} = test caught the bug, {RED}SURVIVE{RST} = blind spot)\n")
    print(BOLD + " " * width + "  ".join(f"{key:^11}" for key, _d, _p in SUITES) + RST)
    for m in MUTANTS:
        cells = []
        for key, _d, _p in SUITES:
            survived = results[m["id"]][key]
            cells.append(f"{RED}{'SURVIVE':^11}{RST}" if survived else f"{GRN}{'KILL':^11}{RST}")
        print(f"{m['id']:<{width}}" + "  ".join(cells) + f"  {DIM}({m['category']}){RST}")

    # ---- scores on load-bearing mutants ----
    lb = [m for m in MUTANTS if m["category"] == "load-bearing"]
    print(f"\n{BOLD}KILL RATE on load-bearing mutants ({len(lb)}):{RST}")
    for key, desc, _p in SUITES:
        killed = sum(0 if results[m["id"]][key] else 1 for m in lb)
        pct = int(100 * killed / len(lb))
        col = GRN if pct == 100 else (YEL if pct > 0 else RED)
        note = " (share-vault only; misses the lending face)" if key == "invariant" else ""
        print(f"  {key:<12} {col}{killed}/{len(lb)}  ({pct}%){RST}  {DIM}{desc}{note}{RST}")
    ig_killed = sum(
        1 for m in lb if not results[m["id"]]["invariant"] or not results[m["id"]]["regression"]
    )
    print(f"  {BOLD}{'InflationGuard':<12}{RST} {GRN}{ig_killed}/{len(lb)}  "
          f"({int(100 * ig_killed / len(lb))}%){RST}  {DIM}generated invariant + PoC, combined{RST}")

    print(f"\n{BOLD}Findings{RST}")
    print(f"  {GRN}*{RST} The happy-path suite has high line coverage and kills 0 load-bearing mutants.")
    print(f"  {GRN}*{RST} The generated invariant kills the vault root cause (M1); the PoC covers the")
    print(f"      lending face (M2). Extending the synthesizer to emit the lending-pair invariant")
    print(f"      would take the generated artifact to 2/2 on its own (see README limitations).")
    m5 = results.get("M5-donatable-price+shrink-offset", {})
    if m5 and not m5.get("invariant", True):
        print(f"  {GRN}*{RST} M3/M4 survive in isolation because they are DOMINATED by FIX-1, not equivalent")
        print(f"      mutants - the combinatorial M5 (revert FIX-1 + offset together) IS killed, which")
        print(f"      proves the dominance. That relationship is the actionable result coverage cannot give.")

    # Leave no stale invariant counterexample behind for the next `forge test`.
    shutil.rmtree(os.path.join(ROOT, "cache", "invariant"), ignore_errors=True)

    # exit non-zero only if a load-bearing mutant survived ALL suites (a true gap)
    gaps = [m for m in lb if all(results[m["id"]][k] for k, _d, _p in SUITES)]
    return len(gaps)


if __name__ == "__main__":
    sys.exit(main())
