# FreightLogic Brand Refresh — 2026-09-13

## Approved direction

The next FreightLogic app icon uses a strong white **F** crossed by an upward road/arrow. It is intended to communicate freight, routing, forward motion, and decision intelligence while remaining legible at iPhone Home Screen and favicon sizes.

Canonical vector source: `FREIGHTLOGIC_MARK_V3.svg`.

Core palette:

- deep navy `#06142F`
- navy `#0B2D5B`
- electric blue `#006BFF`
- cyan `#00D2FF`
- white / ice `#FFFFFF` / `#EAF7FF`

## PWA rollout rule

Do **not** replace only one or two icon sizes. The shipped icon family must stay visually identical across:

`favicon16.png`, `favicon32.png`, `icon64.png`, `icon120.png`, `icon128.png`, `icon152.png`, `icon167.png`, `icon180.png`, `icon192.png`, `icon256.png`, `icon512.png`, and `icon1024.png`.

The raster family has already been generated from the canonical vector source and visually checked at 1024px and iPhone touch-icon scale. Activation should be coordinated with the next shared PWA/cache generation so installed Home Screen clients are not left using a stale cached icon under the same service-worker generation.

This document and vector source do not themselves alter runtime, manifest, service-worker, cache, or installed-PWA behavior.
