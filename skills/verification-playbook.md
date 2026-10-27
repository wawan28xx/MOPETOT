# Secrets & Keys Verification Playbook (MOPETOT)

Evidence-first methodology, adapted from the REA investigation model:
every conclusion must cite evidence (verifier output, decoded values, rule
context). Never claim verified without proof. Full secret values are provided
by MOPETOT on purpose — use them for precise validation, but mask them
(prefix+suffix) in any REPORT DRAFT.

## Validation order (always)
1. IDENTIFY the credential type from rule/category before advising.
2. PASSIVE checks first (format, decode, documentation, provider semantics).
3. ACTIVE checks only via MOPETOT's Live Verifier (already authorized scope).
4. Verdict: CONFIRMED / LIKELY / UNCONFIRMED — state which evidence supports it.
5. If evidence is incomplete, say what is missing. Do not guess.

## Per-type playbook

### AWS (AKIA/ASIA access key)
- Passive: key type (AKIA=long-lived, ASIA=temporary STS). Long-lived = higher impact.
- Evidence ladder: STS GetCallerIdentity (account/user/ARN) → account/permissions
  enumeration → data-plane reach (S3 list, SecretsManager).
- Lateral movement: pivot to cloud console (if console access), enumerate
  cross-account roles, harvest Secrets Manager/SSM values, find ECR/CI tokens.
- Severity: long-lived + broad IAM = P1; temp token = P3-P4 unless scoped.

### Google API key (AIzaSy...)
- NEVER claim "vulnerable" just because the key exists — many are Android/iOS
  app keys restricted by package + SHA1, safe by design.
- Evidence: scope probe results (which APIs answer, which 403 with
  "referer/package restrictions"), Maps key unrestricted billable = P3-P4.
- Lateral movement: if Geocoding/Places unrestricted → abuse billing; if key
  also works on Cloud APIs (translation, vision) → data exfil + cost.
- Verdict "restricted" requires evidence of 403s on restricted endpoints.

### Firebase (Realtime DB / Firestore)
- Evidence: `.json` read test, write test result, rules error message.
- Open read = data exposure (P2-P3, P1 if auth/user data). Open write = P1.
- Lateral movement: enumerate DB tree for admin flags, tokens stored in DB,
  other collections with weaker rules; same service account → other Firebase
  projects (check `projectId` in config).

### Firebase Webconfig API key
- Webconfig API key alone is NOT a vulnerability (it is client-side by
  design). It only becomes one combined with open DB rules or exposed
  service-account credentials. State this explicitly.

### JWT / OAuth tokens (found hardcoded)
- Passive first: decode header+payload (alg, iss, aud, exp, scope claims).
  Hardcoded refresh token with long expiry = P2. Bearer token = P3.
- Lateral movement: use claims to map backend endpoints, check token works
  across environments (staging→prod), check revocation possible.
- NEVER advise sending the raw token anywhere; describe checks conceptually.

### Private keys (RSA/EC/DSA/SSH) — rule requires base64 body, so the key material is present
- Passive: does the header say what it is (client cert vs CA, dev vs prod)?
  Comment field, key size, embedded metadata.
- Impact depends on WHERE it is used (TLS pinning key? signing key?).
- Lateral movement: same private key reused across apps/environments =
  org-level finding (MOPETOT can cross-check via secret reuse).

### Stripe keys
- `pk_live_` = publishable, public by design, NOT a finding alone.
- `sk_live_` = secret key, P1-P2 (charge/refund/read customers).
- Evidence: balance check result from Live Verifier.

### Webhooks (Slack/Discord)
- Evidence: probe result (whoami response).
- Lateral movement: message posting = phishing channel into the org; Discord
  webhooks often leak internal channel names.

### Hardcoded passwords / API creds
- Check the context: config file? dev build? staging URL next to it?
  A dev password is P4; production credential with admin hints = P2-P3.
- Lateral movement: credential reuse across apps (MOPETOT secret-reuse
  cross-check), password spraying org SSO if it looks corporate.

## Severity scale (bug bounty convention)
P1 critical (RCE, full account takeover, prod secret with wide reach) /
P2 high / P3 medium / P4 low / P5 info. When unsure, give the range and the
missing evidence instead of a single number.

## Output format for validation requests
1. VERDICT: CONFIRMED|LIKELY|UNCONFIRMED + one-line reason
2. EVIDENCE: bullet list of what supports it (cite the verifier output)
3. LATERAL MOVEMENT: 2-4 concrete attacker paths, ordered by likelihood
4. SEVERITY: P1-P5 + justification
5. NEXT SAFE STEPS: 2-3 checks the hunter can run (passive first)
6. REPORT DRAFT: 3-5 line summary ready for submission (on request)
