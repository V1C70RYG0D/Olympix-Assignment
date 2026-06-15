# InflationGuard - convenience targets. `make all` runs the full pipeline.
.PHONY: all build test exploit detect semgrep slither synth invariant invariant-vuln mutate clean

SLITHER_PY := $(shell python3 -c "import slither" 2>/dev/null && echo python3 || (head -1 "$$(command -v slither 2>/dev/null)" 2>/dev/null | sed 's/^\#!//'))

all: ## Run the full DETECT -> SYNTHESIZE -> PROVE -> MUTATE pipeline
	bash tool/run.sh

build: ## Compile contracts
	forge build

test: ## Run every Foundry test
	forge test -vv

exploit: ## Reproduce the exploit and show the fix blocks it
	forge test --match-contract ExploitTest -vvv

detect: semgrep slither ## Run both static detectors

semgrep: ## Semgrep ruleset
	semgrep --config tool/inflationguard/semgrep/inflationguard.yml src/

slither: ## Slither semantic detector
	$(SLITHER_PY) tool/inflationguard/inflationguard_slither.py .

synth: ## (Re)generate the invariant suite from the finding
	python3 tool/inflationguard/synthesize_invariant.py

invariant: ## Prove the generated invariant PASSES on the fix
	forge test --match-contract InflationGuardVaultInvariant -vv

invariant-vuln: ## Prove the generated invariant FAILS on the historic bug
	GUARD_TARGET=vulnerable forge test --match-contract InflationGuardVaultInvariant -vv

mutate: ## Mutation gate: who catches the re-introduced bug?
	python3 tool/mutation/mutate.py

clean:
	forge clean
