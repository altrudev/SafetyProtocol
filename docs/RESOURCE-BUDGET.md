# Resource Budget

The security mechanism must remain cheaper than the behavior it governs.

## Core requirements
- deterministic decision path
- no model inference required
- no background polling required by the core
- bounded evidence records
- bounded active probes
- explicit network / CPU / storage budgets
- no mandatory cloud dependency

## Connectivity direction
Adapters should prefer platform events and cached fresh evidence over continuous scans. Active probes should be small, rate-bounded and only used when needed to resolve a decision.

## Compression rule
Do not compress blindly.
- already compressed media: pass through
- encrypted ciphertext: pass through
- text / structured metadata: lightweight compression may be useful
- repeated state: prefer deltas
- reusable assets: cache when policy permits

The objective is fewer transferred bytes with less total work, not maximum compression ratio.
