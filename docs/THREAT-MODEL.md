# Threat Model

Frequency SafetyProtocol assumes external resources can be unavailable, misleading, compromised, stale, malicious, or correctly identified but over-privileged.

## Connectivity threats
- evil-twin / copied SSID
- gateway or DNS substitution
- captive-portal manipulation
- security-mode downgrade
- local peer attacks
- tunnel loss or bypass
- stale trust after network replacement
- deceptive familiarity from reused identifiers
- battery or bandwidth exhaustion through forced probing

## General protocol threats
- capability over-claiming
- stale evidence
- evidence substitution
- adapter claim inflation
- authority confused with availability
- requested authority silently widened during execution
- drift hidden after approval
- receipts claiming more than they observed
- resource exhaustion as a policy bypass
- privacy metadata collected as a side effect of safety evaluation

## Required responses
- unknown does not become trusted
- contradictory evidence grants nothing
- hard drift grants nothing until reevaluation
- authority is intersected with an explicit ceiling
- granted authority never exceeds requested authority
- expired evidence cannot justify promotion
- cost or convenience cannot override a security invariant
- adapters cannot promote evidence strength
- protected public connectivity fails closed when required protection is unavailable

## Out of scope
The protocol does not authorize carrier bypass, credential theft, private-network intrusion, captive-portal circumvention, SIM cloning, surveillance, or unauthorized access.
