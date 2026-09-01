# Changelog

## v1.0.0 - 2026-09-01

Initial launch candidate for Mobile Audit Tool.

### Added

- Web dashboard with dynamic scan listing, filter, and pagination.
- Live Verifier modules:
  - Firebase CRUD exposure check
  - Google API key scope checker (10 endpoints)
  - AWS STS identity probe
  - Stripe key validation
  - Webhook probe (Slack/Discord)
  - Endpoint health probe
  - IP reachability and GeoIP
- Modal detail view for verifier outputs.
- Source context modal for secret findings.
- Deterministic PoC generation endpoint.
- Frida script generation endpoint.

### Changed

- Fast mode behavior:
  - skip JADX
  - skip Blutter
- Live Verifier UX now supports persistence and restore from DB cache.
- PoC section changed to cache-first lazy load with explicit regenerate button.
- PoC heavy generation moved off event loop thread for better UI responsiveness.

### Database

- Added `verification_cache` table for verifier result persistence.
- Added `poc_cache` table for cached PoC payload.

### Notes

- Blutter native build may still be unavailable on some Windows setups due to ICU dependency.
- Tool keeps fallback extraction paths when optional engines are missing.
