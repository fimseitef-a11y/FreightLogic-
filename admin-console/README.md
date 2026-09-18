# FreightLogic Admin Console — Phase A/B draft

This directory is the isolated administrative onboarding surface approved by issue #231.

Security contract:
- separate origin from the driver PWA;
- online-only MVP with no offline credential cache;
- admin access is supplied at runtime and retained only in browser session storage;
- only identity/onboarding operations are available: list, invite, re-invite, revoke;
- driver onboarding uses short-lived claim-code links (`#i=`), never transported permanent driver credentials;
- no freight, trip, expense, receipt, tax, GPS, or driver-history APIs;
- Worker authorization remains authoritative.

## Deployment hold

Do not deploy or merge this surface as production-ready until a real distinct admin origin exists, that exact origin is configured in the Worker CORS allowlist, and live admin-auth/list/invite/re-invite/revoke smoke tests pass. Phase C removal of the legacy driver-app admin surface remains gated on that live proof.
