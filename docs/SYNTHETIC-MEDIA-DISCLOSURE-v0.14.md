# Synthetic Media Disclosure Boundary v0.14

## Status

Experimental SafetyProtocol reference primitive.

This addition separates **synthetic-media disclosure** from **rendering quality**.

The core rule is:

> A visual artifact, facial glitch, identity drift, dropped frame, latency artifact, or other generative imperfection is never evidence that a person was adequately told they are interacting with synthetic media.

Disclosure must be explicit, independently observable, and enforced outside the generative renderer where practical.

## Why this exists

Real-time generative video can occasionally produce unstable facial geometry, expression jumps, frame inconsistencies, or other artifacts. Those artifacts may make a human suspect that content is synthetic, but they are unreliable, non-deterministic, model-dependent, and can disappear as rendering improves.

Treating such artifacts as disclosure would create a perverse safety property: better rendering would silently weaken transparency.

SafetyProtocol therefore models disclosure as a separate control plane.

## Required channels

The reference policy supports three independent channels:

1. **Persistent visual indicator**
   - a human-visible marker that the participant is synthetic;
   - controlled independently from the generated face/scene where practical;
   - absence fails closed for humanlike presentation when required.

2. **Spoken disclosure**
   - an explicit spoken statement at session start;
   - subject to a configurable freshness window;
   - stale or missing confirmation requires refresh.

3. **Watermark/provenance attestation**
   - a machine-verifiable channel that can survive recording or redistribution;
   - treated as provenance evidence, not as a substitute for human-visible disclosure.

## Render quality is diagnostic only

`RenderQuality` can report:

- `Unknown`
- `Stable`
- `Degraded`
- `Unstable`

The disclosure evaluator intentionally ignores it when deciding whether synthetic-media presentation is permitted.

This is a tested invariant.

An unstable renderer with no explicit disclosure fails.

A stable renderer with no explicit disclosure also fails.

A fully disclosed session may continue whether rendering quality is stable or degraded, subject to other product safety policies.

## Decision

`evaluate_synthetic_media_disclosure()` returns:

- whether humanlike presentation is permitted;
- whether a fallback disclosure is required;
- the first unsatisfied required channel.

Current failure reasons are:

- `VisualIndicatorMissing`
- `SpokenDisclosureMissing`
- `SpokenDisclosureStale`
- `WatermarkAttestationMissing`

When all required channels are satisfied:

- `ExplicitDisclosureSatisfied`

## Integration rule

A product integrating this primitive should place the disclosure gate outside the generative renderer where practical.

A safe high-level flow is:

    session starts
        ↓
    explicit disclosure channels established
        ↓
    SafetyProtocol disclosure evaluation
        ↓
    humanlike synthetic presentation permitted
        ↓
    continuous disclosure indicator maintained
        ↓
    spoken disclosure refreshed when required
        ↓
    watermark/provenance evidence retained separately

If a required disclosure channel is lost, the product should stop humanlike presentation or switch to an unmistakable fallback disclosure state until the invariant is restored.

## Threat model

This primitive addresses:

- accidental reliance on AI-looking artifacts as disclosure;
- disappearance of disclosure as generation quality improves;
- watermarking being mistaken for sufficient human disclosure;
- stale one-time spoken disclosure in long-running sessions;
- renderer compromise hiding a disclosure marker if the marker lives only inside generated pixels.

It does not by itself establish:

- cryptographic watermark correctness;
- resistance to all watermark removal;
- legal compliance in every jurisdiction;
- identity verification of the human or synthetic persona;
- consent capture;
- deepfake detection;
- authenticity of upstream source media;
- production video-overlay enforcement.

Those require separate evidence and controls.

## DDC / Frequency boundary

The disclosure claim is deliberately narrow:

**explicit disclosure evidence can authorize synthetic humanlike presentation under the configured policy.**

It does not certify that:

- the generated identity is truthful;
- the model is safe;
- the content is accurate;
- the external user understood or consented;
- the watermark survived downstream transformation.

Those claims need independent evidence.
