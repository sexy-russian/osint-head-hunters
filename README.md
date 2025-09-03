# OSINT Head Hunters — Landing Page + Secure Tip Intake & Admin

## 0) Goal & Scope

Build a public landing page and a secure tip submission system for **OSINT Head Hunters**, an OSINT research agency that collects publicly sourced information to help identify criminal suspects and rewards contributors based on information value.

**In scope**

* Marketing landing page (static + CMS-managed copy).
* Secure tip (“contact”) form with optional anonymity.
* Secure storage (field-level encryption) of tip data & attachments.
* Admin panel (RBAC) to review tips, manage workflow, and record rewards & payouts.
* Payout preference collection (bank, card, crypto) and payout tracking (no payment processing in v1).
* Audit logging, basic analytics, email/PGP notification flow.
* Privacy, consent, and legal compliance scaffolding.

**Out of scope (v1)**

* Automated identity verification of tipsters.
* On-site payment disbursement (manual payout recording only).
* Public “case” pages; API for third parties.

---

## 1) User Roles & Stories

### Public Visitor / Tipster

* As a visitor, I can read what OSINT Head Hunters does and how rewards work.
* As a tipster, I can submit a tip with **optional anonymity** (no real name required).
* As a tipster, I can **securely** upload files (images, docs, archives) and provide links to public sources.
* As a tipster, I can provide **payout preference** (bank, card, crypto) and optional contact for follow-up.
* As a tipster, I must explicitly **consent** that my submission is based on public information and lawful to share.
* As a tipster, I receive a **submission receipt** (on-screen + optional email) with a retrieval code.

### Analyst (Internal)

* Can view submitted tips (decrypted on server), search/filter, and update statuses (New → In Review → Actionable → Closed).
* Can add structured findings/notes, tag by case, and redact sensitive fields where necessary.
* Can assign tips to analysts, track communications with the tipster (if contact provided).

### Admin (Internal)

* Full RBAC management (Admin, Analyst, Read-only).
* Can define reward tiers/criteria, set reward amounts, and mark payouts with date/method/transaction ref.
* Can export **redacted** datasets (CSV/JSON) for reporting.
* Can view audit logs, system health, and storage usage.
* Can configure PGP keys, SMTP, CAPTCHA keys, KMS key alias, retention policies.

---

## 2) Functional Requirements

### 2.1 Landing Page (Public)

Sections:

* **Hero**: Brand (“OSINT Head Hunters”), concise value prop, primary CTA “Submit a Tip Securely”.
* **How it Works**: 3–4 steps (Submit → Verify → Reward → Impact).
* **What We Collect** (strictly public OSINT): location leads, contact leads, identifiers, open sources.
* **Reward Model**: General guidance; not a contract. Link to detailed Terms.
* **Trust & Safety**: Data handling, encryption, anonymity option, legal compliance, whistleblower-friendly language.
* **FAQ**: Eligibility, what not to submit, expected timelines (no guarantees), payout methods supported.
* **Footer**: Terms, Privacy, Lawful Use Notice, Contact (PGP fingerprint), social.

### 2.2 Secure Tip Form (Public)

* **Anonymity toggle**: On by default; when off, show optional name/contact fields.
* **Fields** (all encrypted at rest unless noted):

  * `tip_title` (short text)
  * `summary` (rich text — sanitized markdown)
  * `targets` (structured array): suspected person/organization names (text); optional aliases.
  * `location_leads` (text): addresses/areas, coordinates if known; **do not encourage private info**.
  * `contact_leads` (text): public phone/email/handles/URLs only.
  * `evidence_links` (array of URLs to public sources)
  * `attachments` (files; virus-scanned; allowed types: jpg/png/gif/pdf/txt/csv/zip; max size per file & total)
  * `how_obtained` (select): “Public source”, “Own observation”, “Other (describe)”
  * `sensitivity_notes` (text): anything that requires careful handling
  * `payout_preference`:

    * `method` (enum): Bank | Card | Crypto | None
    * If Bank: holder name, country, IBAN/Account # (masked in UI), SWIFT/BIC
    * If Card: card network (no PAN), payout handle/token if supported (we only store token/handle)
    * If Crypto: network (BTC/ETH/TON/etc.), address
  * `contact_email` (optional), `contact_matrix/telegram/signal` (optional handles), or **PGP public key** (text)
  * `consent_checkboxes` (must-check):

    * “I am submitting information obtained lawfully from public sources or with permission.”
    * “I agree to the Terms & Privacy Policy.”
    * “I understand OSINT Head Hunters may not take action or issue a reward.”
* **Validation**

  * URL validation, length limits, server-side sanitation (HTML stripped from text).
  * Rate limiting + CAPTCHA (Cloudflare Turnstile or reCAPTCHA).
* **Submission UX**

  * On success: show receipt with `submission_id` + `retrieval_code`.
  * Optional email receipt (if email provided).
  * Thank-you copy with safety disclaimer.
* **Security**

  * TLS 1.3; HSTS; CSRF protection; server-side validation; file antivirus scan (e.g., ClamAV).
  * Field-level encryption (see §4).

### 2.3 Admin Panel (Internal)

* **Auth**

  * SSO (OIDC/SAML) if available; otherwise email+password + TOTP 2FA.
  * RBAC: Admin, Analyst, Read-only. Principle of least privilege.
* **Tip Management**

  * Filter/search by status, tags, date, keyword, target, analyst.
  * Detail view: decrypt on server; show timeline, attachments (download with expiring URLs), notes.
  * Actions: Assign, Change status, Add internal notes, Redact fields, Merge duplicate tips, Tag to Case.
* **Rewards & Payouts**

  * Define reward decision: `reward_amount`, `currency`, `rationale`, `approver_id`.
  * Payout record: `payout_method`, `payout_reference`, `payout_date`, `status` (Pending/Paid/Failed).
  * Never display full bank/card numbers; only masked identifiers or payout tokens.
* **Audit & Reporting**

  * Immutable audit log of tip access, field decryption, edits, exports, payout changes.
  * Export redacted CSV/JSON with configurable field whitelist.
* **Config**

  * Manage KMS alias, retention policy, SMTP, PGP keys, CAPTCHA keys, allowed file types/sizes, reward currencies.

---

## 3) Non-Functional Requirements

* **Performance**: TTFB < 200ms cached; form submission < 2s under p95; assets via CDN.
* **Accessibility**: WCAG 2.1 AA; keyboard navigable; proper labels, aria attributes.
* **i18n-ready**: English first; framework support for locales.
* **Observability**: Structured logs (no PII), metrics (latency, errors), alerting (pager/email).

---

## 4) Security & Privacy (Mandatory)

* **Transport**: HTTPS+HSTS. Disable weak ciphers. Secure cookies (HttpOnly, SameSite=Strict).
* **Storage Encryption**:

  * Use **envelope encryption**: Master keys in **AWS KMS** (separate CMK alias e.g., `alias/osint-tips`).
  * Generate **data-encryption keys (DEKs)** per record; encrypt sensitive fields with **AES-256-GCM**; store DEKs encrypted with KMS (EDEK).
  * Sensitive fields (encrypt at field level): `summary`, `targets`, `location_leads`, `contact_leads`, `evidence_links`, `attachments metadata`, `payout_preference.*`, `contact_*`, `sensitivity_notes`.
  * Hash searchable fields using keyed HMAC (e.g., HMAC-SHA-256) for equality search without plaintext.
* **Access Control**:

  * Server-side authorization checks; deny by default.
  * Row-level access (analysts see only assigned unless Admin).
* **Key Management**:

  * Key rotation policy every 6–12 months; rewrap EDEKs.
  * Separate staging and prod KMS keys; no key sharing across envs.
* **Backups**:

  * Encrypted backups with key separation; tested restore process; backup retention policy.
* **Attachments**:

  * Store in S3 with **SSE-KMS**; access via short-lived pre-signed URLs; AV scan **before** persistence.
* **Secrets**:

  * Use AWS Secrets Manager (or Vault) for DB creds, SMTP, OAuth secrets.
* **Audit**:

  * Log every decrypt, read, export, payout change with actor, timestamp, purpose.
* **Abuse & Legal Safeguards**:

  * Enforce Terms prohibiting doxxing, private credentials, medical/financial records, or hacked data.
  * Accept **public OSINT only**; display warnings and inline examples.
  * Redaction controls in Admin; mandatory reason for viewing highly sensitive fields.
  * Data retention: default 18 months (configurable) then purge/cryptoshred.
  * DSR (data subject request) workflow and incident response playbook.

---

## 5) Tech Stack

### Option A (JS/TS full-stack)

* **Frontend**: Next.js (App Router), TypeScript, TailwindCSS, shadcn/ui, Zod for schema validation.
* **Backend**: NestJS (TypeScript), PostgreSQL (RDS/Aurora), Prisma ORM.
* **Storage**: S3 (+ SSE-KMS) for attachments.
* **Infra**: AWS (CloudFront, WAF, ALB, ECS/Fargate or Lambda), Route53.
* **CI/CD**: GitHub Actions; OPA/ESLint/Prettier; Trivy/Snyk scans.

### Option B (Python)

* **Frontend**: Next.js as above.
* **Backend**: Django + Django REST Framework; django-axes, django-otp; Celery for AV scans & emails.
* **DB/Infra**: Postgres + AWS stack as above.

Pick one and stick to it; both meet requirements.

---

## 6) Data Model (proposed, Postgres)

```
users (
  id uuid pk, email citext unique, role enum('admin','analyst','readonly'),
  password_hash text null, totp_secret text null, sso_sub text null,
  created_at timestamptz, updated_at timestamptz
)

tips (
  id uuid pk, submission_id text unique, retrieval_code_hash text,
  status enum('new','in_review','actionable','closed') default 'new',
  tip_title text,
  summary_enc bytea, summary_aad text,
  targets_enc bytea, location_leads_enc bytea, contact_leads_enc bytea,
  evidence_links_enc bytea, sensitivity_notes_enc bytea,
  how_obtained text,
  payout_method enum('bank','card','crypto','none') default 'none',
  payout_details_enc bytea,
  contact_channels_enc bytea,
  contact_email_hmac bytea,   -- for dedupe without plaintext
  edek bytea,                  -- KMS-encrypted DEK
  created_at timestamptz, created_ip inet, ua text
)

attachments (
  id uuid pk, tip_id uuid fk, s3_key text, sha256 bytea,
  mime text, size bigint, av_status enum('pending','clean','infected'),
  created_at timestamptz
)

notes (
  id uuid pk, tip_id uuid fk, author_id uuid fk,
  body_enc bytea, created_at timestamptz
)

tip_assignments (
  tip_id uuid fk, analyst_id uuid fk, assigned_at timestamptz, primary key(tip_id, analyst_id)
)

rewards (
  id uuid pk, tip_id uuid fk,
  amount numeric(12,2), currency char(3),
  rationale text, approver_id uuid fk, decided_at timestamptz
)

payouts (
  id uuid pk, reward_id uuid fk,
  method enum('bank','card','crypto'),
  reference text, status enum('pending','paid','failed') default 'pending',
  paid_at timestamptz
)

audit_logs (
  id bigserial pk, actor_id uuid null, action text,
  tip_id uuid null, details jsonb, occurred_at timestamptz
)

cases (
  id uuid pk, name text, description text, created_at timestamptz
)

tip_cases (
  tip_id uuid fk, case_id uuid fk, primary key (tip_id, case_id)
)
```

---

## 7) API Endpoints (sketch)

**Public**

* `POST /api/v1/tips` — create tip (rate-limited, CAPTCHA). Server handles encryption before DB.
* `POST /api/v1/tips/:id/attachments` — upload (pre-signed URL), AV scan job.
* `POST /api/v1/tips/:id/confirm` — optional email confirmation if provided.

**Admin**

* `GET /api/v1/admin/tips?filters` — search (returns metadata; decrypt specific fields on detail call).
* `GET /api/v1/admin/tips/:id` — detail (server decrypts, policy checks).
* `PATCH /api/v1/admin/tips/:id` — status/assignment/redaction updates.
* `POST /api/v1/admin/tips/:id/notes` — add internal notes.
* `POST /api/v1/admin/rewards` — create/update reward.
* `POST /api/v1/admin/payouts` — record payout.
* `GET /api/v1/admin/exports` — redacted export (streamed CSV/JSON).
* `GET /api/v1/admin/audit` — audit log (paginated).

All admin routes require auth + 2FA + RBAC.

---

## 8) UX & Content Notes

* Tone: professional, safety-first, whistleblower-aware.
* Prominent notices: “Submit **publicly sourced** information only.” Examples of acceptable vs. prohibited content.
* CTA buttons: “Submit a tip securely”, “How rewards work”.
* Show PGP fingerprint and downloadable public key on Contact page.

---

## 9) Compliance & Legal Checklist

* Publish **Terms of Service** and **Privacy Policy** (provided by counsel).
* GDPR/CCPA readiness: data map, DSR inbox, documented retention, breach notification plan.
* Lawful use & cooperation statement; jurisdiction disclosure.
* Cookie banner (strictly necessary by default; analytics only with consent).

---

## 10) DevSecOps, Testing, & Monitoring

* **CI**: lint, typecheck, unit tests, SCA (Snyk/Trivy).
* **Tests**: unit (schemas, crypto utils), integration (encryption round-trip, uploads, AV), e2e (form → admin workflow), a11y tests.
* **Security tests**: OWASP ASVS checklist, SSRF/file upload hardening, authZ tests, dependency scans, container scans.
* **Monitoring**: app metrics, error tracking (Sentry), WAF logs, AV stats, KMS key usage alarms.
* **Rate limiting**: per IP + global; allowlist internal ranges.

---

## 11) Content Security Policy (CSP) & Headers

* Strict CSP (script-src self plus analytics domain if enabled).
* X-Content-Type-Options: nosniff; Referrer-Policy: no-referrer; Permissions-Policy: minimal.
* Disable directory listing; deny framing; set COOP/COEP if feasible.

---

## 12) Analytics (Privacy-Preserving)

* Server-side, aggregated page views and conversions; no per-user PII.
* Optional privacy-preserving analytics (e.g., Plausible/Matomo) with consent.

---

## 13) Acceptance Criteria

* Landing page loads < 2 MB total; Lighthouse >= 90 (PWA not required).
* Tip form:

  * Submits successfully with/without contact.
  * All sensitive fields verified encrypted at rest (manual check via DB dump shows ciphertext).
  * Attachments scanned; infected files are rejected.
  * CAPTCHA and rate limits enforced.
  * Consent checkboxes enforced (no submission without consent).
* Admin:

  * RBAC enforced (read-only cannot decrypt).
  * Status workflow works; audit logs show each decrypt/action.
  * Reward and payout records can be created and reported on.
  * Redacted export excludes encrypted fields unless explicitly whitelisted.
* Security:

  * KMS keys used; DEK rotation script exists and passes tests.
  * Secrets in Secrets Manager; no secrets in repo or env files committed.

---

## 14) Deliverables

* Source code repos (frontend, backend, infra/IaC).
* IaC (Terraform or CDK) for AWS resources (VPC, RDS, S3, CloudFront, WAF, KMS, IAM).
* Runbooks: onboarding, key rotation, incident response, backup/restore.
* Admin user guide and redaction workflow guide.
* Terms/Privacy templates placeholders wired to UI.

---

## 15) Ethical Guardrails (must appear in UI and docs)

* Accept **only** public OSINT; prohibit private/confidential data, hacked content, minors’ data, medical/financial records, or vigilante actions.
* Clear statement: all submissions are reviewed for legality; cooperating with lawful authorities where required.
* Easy takedown request process for affected parties.

---

### Brand & Visual

* **Brand name**: **OSINT Head Hunters**
* Minimal, trustworthy palette; clear security cues; accessible typography; no sensational imagery.
