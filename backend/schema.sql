-- Driftband schema. Applied idempotently at startup.

CREATE TABLE IF NOT EXISTS organizations (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  retention_years INT  NOT NULL DEFAULT 1 CHECK (retention_years BETWEEN 1 AND 3),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  org_id        BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member',  -- owner | admin | member
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Columns added by later schema versions (idempotent).
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name     TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name      TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret    TEXT;              -- sealed ("enc:" + base64, see totp.go); set during 2FA enrollment
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;  -- last accepted TOTP step (replay guard)
-- Platform administration. is_superadmin is granted only directly in the
-- database (no API sets it); disabled blocks sign-in and ends sessions.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false;
-- Maximum number of hosts (NULL = instance default: unlimited, or 10 on a test instance).
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS host_limit INT CHECK (host_limit >= 0);
-- Set by a platform admin: test-instance limits (TEST_INSTANCE) do not apply.
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS exempt_limits BOOLEAN NOT NULL DEFAULT false;

-- Set whenever a session is created (sign-in, registration, accepted invite).
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- Security keys and passkeys (WebAuthn) as second factors. kind is what the
-- user enrolled: 'key' (a roaming hardware key such as a YubiKey) or
-- 'passkey' (a discoverable credential with user verification: this device,
-- a phone or a password manager). credential_id is the lookup key; data is
-- the credential record (public key, counter, flags) as sealed JSON, so a
-- row added or changed directly in the database is not accepted.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,   -- key | passkey
  name          TEXT NOT NULL,
  credential_id BYTEA NOT NULL UNIQUE,
  data          BYTEA NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);

-- Pending WebAuthn ceremonies (enrollment or sign-in): the challenge issued
-- to one user, valid for a few minutes and usable once.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  token      TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    TEXT NOT NULL,   -- register | login
  kind       TEXT NOT NULL DEFAULT '',
  name       TEXT NOT NULL DEFAULT '',
  data       JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

-- Profile pictures: always re-encoded by the server to a small square image
-- (see avatar.go), never the uploaded file itself.
CREATE TABLE IF NOT EXISTS user_avatars (
  user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  mime       TEXT NOT NULL,   -- image/jpeg | image/png
  data       BYTEA NOT NULL,
  etag       TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
  token      TEXT PRIMARY KEY,
  org_id     BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role       TEXT NOT NULL DEFAULT 'member',
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS probe_profiles (
  id          BIGSERIAL PRIMARY KEY,
  org_id      BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  interval_s  INT NOT NULL CHECK (interval_s >= 5),
  ping_count  INT NOT NULL CHECK (ping_count BETWEEN 1 AND 100),
  packet_size INT NOT NULL CHECK (packet_size BETWEEN 12 AND 65000),
  is_default  BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tree of folders and hosts (SmokePing-style + / ++ / +++ nesting).
CREATE TABLE IF NOT EXISTS nodes (
  id          BIGSERIAL PRIMARY KEY,
  org_id      BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  parent_id   BIGINT REFERENCES nodes(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,  -- folder | host
  name        TEXT NOT NULL,
  host        TEXT,           -- IP/hostname (kind=host)
  description TEXT,
  profile_id  BIGINT REFERENCES probe_profiles(id) ON DELETE SET NULL,
  position    INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_nodes_org    ON nodes(org_id);
CREATE INDEX IF NOT EXISTS idx_nodes_parent ON nodes(parent_id);

-- Raw probe samples (one row per cycle). Percentiles are computed on read.
CREATE TABLE IF NOT EXISTS samples (
  host_id BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  ts      TIMESTAMPTZ NOT NULL,
  sent    INT NOT NULL,
  recv    INT NOT NULL,
  rtts    DOUBLE PRECISION[] NOT NULL,
  PRIMARY KEY (host_id, ts)
);
-- Every read is per host and the primary key serves both scan directions,
-- so the old (host_id, ts DESC) index only cost space and write time.
DROP INDEX IF EXISTS idx_samples_host_ts;

-- Pre-aggregated samples for long windows (SmokePing RRA style), maintained by
-- the rollup worker. res = bucket width in seconds (300 | 3600), ts = bucket
-- start. pct holds the percentiles of all RTTs pooled across the bucket
-- (p0,p2.5,p10,p25,p50,p75,p90,p97.5,p100; NULL when nothing replied). The
-- med_* / loss_* columns let window statistics be summed exactly from rollups.
CREATE TABLE IF NOT EXISTS sample_rollups (
  host_id     BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  res         INT NOT NULL,
  ts          TIMESTAMPTZ NOT NULL,
  cycles      INT NOT NULL,
  sent        INT NOT NULL,
  recv        INT NOT NULL,
  pct         DOUBLE PRECISION[],
  med_n       INT NOT NULL,               -- cycles with at least one reply
  med_sum     DOUBLE PRECISION NOT NULL,  -- sum of per-cycle medians
  med_sq      DOUBLE PRECISION NOT NULL,  -- sum of squared per-cycle medians
  loss_cycles INT NOT NULL,               -- cycles with any loss
  loss_max    DOUBLE PRECISION NOT NULL,  -- max per-cycle loss fraction
  loss_min    DOUBLE PRECISION NOT NULL,  -- min per-cycle loss fraction
  PRIMARY KEY (host_id, res, ts)
);

-- Autovacuum for the bulk tables. Deleting a host removes months of its
-- samples at once; with the default threshold (20 % of the table) that space
-- would wait for millions of dead rows. Here a vacuum starts after 1000 dead
-- rows, within a minute, and runs at disk speed (higher cost limit); the
-- freed pages are reused for new samples (the files do not shrink).
-- Insert-only growth is vacuumed every 5 % so later vacuums stay cheap.
ALTER TABLE samples SET (
  autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 1000,
  autovacuum_vacuum_insert_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02,
  autovacuum_vacuum_cost_limit = 2000);
ALTER TABLE sample_rollups SET (
  autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 1000,
  autovacuum_vacuum_insert_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02,
  autovacuum_vacuum_cost_limit = 2000);

-- Rollups of every tier are complete for samples with ts < done_until.
CREATE TABLE IF NOT EXISTS rollup_state (
  host_id    BIGINT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  done_until TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         BIGSERIAL PRIMARY KEY,
  org_id     BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id    BIGINT REFERENCES users(id) ON DELETE SET NULL,
  user_email TEXT,
  action     TEXT NOT NULL,
  detail     TEXT,
  ip         TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, created_at DESC);
-- System events and failed logins for unknown emails have no organization.
ALTER TABLE audit_log ALTER COLUMN org_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

-- Daily database size snapshots for the admin usage trend and forecast.
CREATE TABLE IF NOT EXISTS db_size_history (
  day           DATE PRIMARY KEY,
  total_bytes   BIGINT NOT NULL,
  samples_bytes BIGINT NOT NULL,
  rollups_bytes BIGINT NOT NULL,
  samples_rows  BIGINT NOT NULL
);

-- ----- notifications -----

-- Application-wide settings (e.g. the generated secrets key when SECRET_KEY
-- is not provided in the environment).
CREATE TABLE IF NOT EXISTS app_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Where alerts are delivered. secret holds the channel's settings and
-- secrets (addresses, accounts, recipients, tokens, webhook URLs, passwords)
-- as sealed JSON: AES-256-GCM under a key derived from the master key and a
-- per-row salt. Only the name and kind are in clear. Rows written before
-- enc_version 2 (settings in config, unsalted secrets) are re-sealed at
-- startup; config is empty afterwards.
CREATE TABLE IF NOT EXISTS notify_channels (
  id         BIGSERIAL PRIMARY KEY,
  org_id     BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,               -- telegram | slack | teams | email
  config     JSONB NOT NULL DEFAULT '{}',
  secret     BYTEA,
  enabled    BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notify_channels_org ON notify_channels(org_id);
ALTER TABLE notify_channels ADD COLUMN IF NOT EXISTS enc_version INT NOT NULL DEFAULT 1;

-- When to alert. A rule watches every host in its scope (node_id NULL = all
-- hosts of the org, a folder = its subtree, a host = that host).
CREATE TABLE IF NOT EXISTS alert_rules (
  id                  BIGSERIAL PRIMARY KEY,
  org_id              BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                TEXT NOT NULL,
  enabled             BOOLEAN NOT NULL DEFAULT true,
  node_id             BIGINT REFERENCES nodes(id) ON DELETE CASCADE,
  metric              TEXT NOT NULL,      -- loss (%) | latency (median ms)
  threshold           DOUBLE PRECISION NOT NULL,
  recover_threshold   DOUBLE PRECISION NOT NULL,
  for_minutes         INT NOT NULL,       -- breach must last this long to fire
  recover_minutes     INT NOT NULL,       -- recovery must last this long to resolve
  notify_recovery     BOOLEAN NOT NULL DEFAULT true,
  repeat_minutes      INT NOT NULL DEFAULT 0,   -- reminder while firing, 0 = never
  flap_transitions    INT NOT NULL DEFAULT 4,   -- 0 disables flap detection
  flap_window_minutes INT NOT NULL DEFAULT 60,
  channel_ids         BIGINT[] NOT NULL DEFAULT '{}',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_org ON alert_rules(org_id);

-- Evaluator state per rule and host.
CREATE TABLE IF NOT EXISTS alert_state (
  rule_id       BIGINT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  host_id       BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  firing        BOOLEAN NOT NULL DEFAULT false,
  flapping      BOOLEAN NOT NULL DEFAULT false,
  since         TIMESTAMPTZ NOT NULL DEFAULT now(),  -- last change of firing
  breach_since  TIMESTAMPTZ,                         -- condition continuously true since
  clear_since   TIMESTAMPTZ,                         -- recovery continuously true since
  transitions   TIMESTAMPTZ[] NOT NULL DEFAULT '{}', -- firing changes inside the flap window
  last_notified TIMESTAMPTZ,
  last_value    DOUBLE PRECISION,
  PRIMARY KEY (rule_id, host_id)
);

-- Delivery history.
CREATE TABLE IF NOT EXISTS notify_log (
  id         BIGSERIAL PRIMARY KEY,
  org_id     BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id    BIGINT REFERENCES alert_rules(id) ON DELETE SET NULL,
  host_id    BIGINT REFERENCES nodes(id) ON DELETE SET NULL,
  channel_id BIGINT REFERENCES notify_channels(id) ON DELETE SET NULL,
  event      TEXT NOT NULL,   -- firing | resolved | reminder | flapping | flapping_end | test
  message    TEXT NOT NULL,
  ok         BOOLEAN NOT NULL,
  error      TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notify_log_org ON notify_log(org_id, created_at DESC);
