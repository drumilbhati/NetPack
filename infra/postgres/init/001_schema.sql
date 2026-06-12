CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'case_status') THEN
    CREATE TYPE case_status AS ENUM ('open', 'closed', 'archived');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'evidence_status') THEN
    CREATE TYPE evidence_status AS ENUM ('registered', 'parsing', 'parsed', 'failed', 'retrying');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_status') THEN
    CREATE TYPE job_status AS ENUM ('queued', 'running', 'succeeded', 'failed', 'retrying');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alert_status') THEN
    CREATE TYPE alert_status AS ENUM ('open', 'investigating', 'confirmed', 'false_positive', 'closed');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role_id UUID NOT NULL REFERENCES roles(id),
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS investigators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  display_name TEXT NOT NULL,
  email TEXT UNIQUE,
  badge_number TEXT UNIQUE,
  agency TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_number TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT,
  status case_status NOT NULL DEFAULT 'open',
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS case_members (
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, user_id)
);

CREATE TABLE IF NOT EXISTS evidence_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
  original_filename TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  sha256 CHAR(64) NOT NULL,
  byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
  content_type TEXT,
  status evidence_status NOT NULL DEFAULT 'registered',
  parser_version TEXT,
  uploaded_by UUID REFERENCES users(id),
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  parsed_at TIMESTAMPTZ,
  failure_reason TEXT,
  UNIQUE (case_id, id),
  UNIQUE (case_id, sha256)
);

CREATE TABLE IF NOT EXISTS parser_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evidence_id UUID NOT NULL REFERENCES evidence_files(id) ON DELETE CASCADE,
  status job_status NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
  parser_version TEXT NOT NULL,
  locked_by TEXT,
  locked_at TIMESTAMPTZ,
  run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_parser_jobs_one_active_per_evidence
  ON parser_jobs(evidence_id)
  WHERE status IN ('queued', 'running', 'retrying');

CREATE TABLE IF NOT EXISTS custody_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
  evidence_id UUID,
  actor_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (case_id, evidence_id) REFERENCES evidence_files(case_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID REFERENCES users(id),
  actor_role TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id UUID,
  case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
  evidence_id UUID,
  request_id TEXT,
  request_ip INET,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CHECK (evidence_id IS NULL OR case_id IS NOT NULL),
  FOREIGN KEY (case_id, evidence_id) REFERENCES evidence_files(case_id, id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  evidence_id UUID NOT NULL,
  source TEXT NOT NULL,
  rule_or_model_id TEXT NOT NULL,
  rule_or_model_version TEXT,
  severity TEXT NOT NULL,
  status alert_status NOT NULL DEFAULT 'open',
  title TEXT NOT NULL,
  explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
  flow_reference JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (evidence_id, source, rule_or_model_id, flow_reference),
  FOREIGN KEY (case_id, evidence_id) REFERENCES evidence_files(case_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  generated_by UUID REFERENCES users(id),
  object_key TEXT NOT NULL UNIQUE,
  sha256 CHAR(64) NOT NULL,
  report_type TEXT NOT NULL,
  generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_evidence_files_case_id ON evidence_files(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_files_case_id_id ON evidence_files(case_id, id);
CREATE INDEX IF NOT EXISTS idx_evidence_files_sha256 ON evidence_files(sha256);
CREATE INDEX IF NOT EXISTS idx_investigators_email ON investigators(email);
CREATE INDEX IF NOT EXISTS idx_parser_jobs_status_run_after ON parser_jobs(status, run_after);
CREATE INDEX IF NOT EXISTS idx_custody_events_case_evidence_time ON custody_events(case_id, evidence_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_case_time ON audit_events(case_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_alerts_case_status ON alerts(case_id, status);

INSERT INTO roles (name)
VALUES ('admin'), ('investigator'), ('auditor')
ON CONFLICT (name) DO NOTHING;
