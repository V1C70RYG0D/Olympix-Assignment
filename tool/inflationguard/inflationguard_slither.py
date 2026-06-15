#!/usr/bin/env python3
"""
InflationGuard - semantic Slither detector for donation / rounding share-inflation.

This is the second, "production-grade" detector layer. Where the Semgrep rules
match syntax, this walks Slither's compiled AST/IR so it can reason about
*relationships*: which value feeds a price, whether a conversion carries a
virtual-shares offset, whether a deposit guards its share output, and whether an
inverse rate can floor to zero unguarded.

It encodes the unifying property distilled from zkLend (Feb 2025), Resupply
(Jun 2025) and the ERC-4626 first-depositor lineage:

    A security-relevant value (price / shares / exchange rate) is produced by a
    truncating division whose per-share scaling factor is attacker-movable
    (a donatable balance, on an emptiable pool with no virtual-shares floor),
    and whose rounding direction or zero-collapse benefits the caller.

Usage:
    python3 tool/inflationguard/inflationguard_slither.py [TARGET]
        TARGET defaults to "." (the Foundry project). Only contracts under
        src/ are reported. Exit code is the number of high-severity findings
        (so it can gate CI).
"""
import sys
import re

try:
    from slither import Slither
except Exception as e:  # pragma: no cover
    print("ERROR: slither is not importable. `pip install slither-analyzer`.")
    print(f"  ({e})")
    sys.exit(2)


RED = "\033[91m"
YEL = "\033[93m"
CYN = "\033[96m"
GRN = "\033[92m"
DIM = "\033[2m"
RST = "\033[0m"


class Finding:
    __slots__ = ("sev", "rule", "contract", "func", "line", "msg", "file")

    def __init__(self, sev, rule, contract, func, line, msg, file=""):
        self.sev, self.rule, self.contract = sev, rule, contract
        self.func, self.line, self.msg, self.file = func, line, msg, file

    def to_dict(self):
        return {
            "severity": self.sev, "rule": self.rule, "contract": self.contract,
            "function": self.func, "line": self.line, "file": self.file, "message": self.msg,
        }


def _exprs(func):
    """All stringified node expressions in a function (Slither-parsed)."""
    out = []
    for n in func.nodes:
        if n.expression is not None:
            out.append(str(n.expression))
    return out


def _line(func):
    try:
        return func.source_mapping.lines[0]
    except Exception:
        return 0


def _has_require_gt_zero(func, var_hint=None):
    """True if the function requires some value > 0 (optionally matching a hint)."""
    for n in func.nodes:
        e = str(n.expression) if n.expression is not None else ""
        if "require" in e and "> 0" in e:
            if var_hint is None or var_hint in e:
                return True
    return False


def _reads_donatable_balance(func):
    """A value read from balanceOf(address(this)) - donatable price source."""
    for e in _exprs(func):
        s = e.replace(" ", "")
        if "balanceOf(address(this))" in s or "balanceOf(this)" in s:
            return e
    return None


def _is_conversion(func):
    name = func.name.lower()
    return name.startswith("convertto") or name in ("pricepershare", "exchangerate", "getprices")


def _division_exprs(func):
    return [e for e in _exprs(func) if "/" in e]


def _has_virtual_offset(func):
    """A conversion is dampened if its share math adds a constant (virtual shares
    / +1 virtual asset). Detect an addition involving a literal or 10 ** k."""
    for e in _exprs(func):
        if "/" in e and ("+" in e):
            # e.g. (totalSupply + 10 ** OFFSET) / (totalAssets() + 1)
            if re.search(r"\+\s*\d", e) or "10 **" in e or "10**" in e or "+ 1" in e or "+1" in e:
                return True
    return False


def analyze(target):
    sl = Slither(target)
    findings = []

    for c in sl.contracts_derived:
        sm = c.source_mapping
        path = getattr(sm, "filename", None)
        fname = getattr(path, "relative", "") if path else ""
        if "/src/" not in f"/{fname}" and not fname.startswith("src/"):
            continue
        if c.is_interface or c.name.lower().startswith("mock") or "ERC20" in c.name:
            continue

        is_vaultish = any(
            v.name in ("totalSupply", "totalAssets") for v in c.state_variables
        ) or any(f.name.lower().startswith("convertto") for f in c.functions)

        for f in c.functions_declared:
            if f.is_constructor or not f.nodes:
                continue

            # ---- RULE 1: donatable price source -------------------------------
            don = _reads_donatable_balance(f)
            if don and (f.view or _is_conversion(f) or f.name in ("totalAssets", "price")):
                findings.append(Finding(
                    "HIGH", "donatable-price-source", c.name, f.name, _line(f),
                    "price/total-assets read from balanceOf(address(this)); a token "
                    "donation moves it. Use internal accounting.",
                ))

            # ---- RULE 2: conversion without virtual-shares offset -------------
            if _is_conversion(f) and _division_exprs(f) and not _has_virtual_offset(f):
                # only meaningful for the asset<->share conversions, not the rate inverse
                if f.name.lower().startswith("convertto"):
                    findings.append(Finding(
                        "HIGH", "no-virtual-shares-offset", c.name, f.name, _line(f),
                        "asset<->share conversion uses raw division with no virtual-shares "
                        "offset; an emptied pool can be inflated to an extreme price.",
                    ))

            # ---- RULE 3: inverse rate that can floor to zero ------------------
            for e in _division_exprs(f):
                s = e.replace(" ", "")
                if re.search(r"(RATE_PRECISION|1e36|1000000000000000000000000000000000000)/", s):
                    if not _has_require_gt_zero(f):
                        findings.append(Finding(
                            "HIGH", "inverse-rate-floor-to-zero", c.name, f.name, _line(f),
                            "exchange rate = CONST / price via truncating division with no "
                            "require(rate > 0); an inflated price floors the rate to 0 and "
                            "disables the solvency check (Resupply).",
                        ))
                        break

            # ---- RULE 4: deposit mints shares without a > 0 guard -------------
            if f.name.lower() in ("deposit", "mint") and is_vaultish:
                calls_conv = any("convertToShares" in e for e in _exprs(f))
                if calls_conv and not _has_require_gt_zero(f):
                    findings.append(Finding(
                        "MEDIUM", "deposit-missing-nonzero-shares", c.name, f.name, _line(f),
                        "deposit computes shares then pulls assets without "
                        "require(shares > 0); a non-zero deposit can mint 0 shares.",
                    ))

        # stamp the source file onto every finding for this contract (one file per contract)
        for fd in findings:
            if not fd.file and fd.contract == c.name:
                fd.file = fname

    return findings


def main():
    import json
    as_json = "--json" in sys.argv
    exclude_path = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--exclude-path=")), None)
    args = [a for a in sys.argv[1:] if a != "--json" and not a.startswith("--exclude-path=")]
    target = args[0] if args else "."
    findings = analyze(target)
    if exclude_path:
        findings = [f for f in findings if exclude_path not in f.file]

    if as_json:
        # Machine-readable output consumed by synthesize_invariant.py --from-finding
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return sum(1 for f in findings if f.sev == "HIGH")

    try:
        from importlib.metadata import version as _pkg_version
        ver = _pkg_version("slither-analyzer")
    except Exception:
        ver = "?"
    print(f"{CYN}InflationGuard (Slither {ver}){RST}  target={target}\n")

    if not findings:
        print(f"{GRN}No donation/rounding inflation patterns found.{RST}")
        return 0

    highs = 0
    for fd in sorted(findings, key=lambda x: (x.contract, x.line)):
        color = RED if fd.sev == "HIGH" else YEL
        if fd.sev == "HIGH":
            highs += 1
        print(f"{color}[{fd.sev}]{RST} {color}{fd.rule}{RST}")
        print(f"      {fd.contract}.{fd.func}  {DIM}(src line {fd.line}){RST}")
        print(f"      {fd.msg}\n")

    print(f"{DIM}{'-'*64}{RST}")
    print(f"{RED}{highs} HIGH{RST}, {YEL}{len(findings)-highs} MEDIUM{RST}  "
          f"across {len(set(f.contract for f in findings))} contracts.")
    return highs


if __name__ == "__main__":
    sys.exit(main())
