ALTER TABLE users
  ADD COLUMN IF NOT EXISTS password_hash TEXT;

INSERT INTO users (email, display_name, role_id, is_active, password_hash)
SELECT 'admin@netpack.local', 'NetPack Admin', r.id, true,
       'pbkdf2_sha256$310000$5a6f3dcb66d46d9b9d0f9f10e0dc8b91$2090298ca851568e70eb2eb21fd20a989548e8e1b6294e42778fa384fdbf8eb7'
FROM roles r
WHERE r.name = 'admin'
ON CONFLICT (email) DO UPDATE
SET display_name = EXCLUDED.display_name,
    role_id = EXCLUDED.role_id,
    is_active = true,
    password_hash = EXCLUDED.password_hash;

INSERT INTO users (email, display_name, role_id, is_active, password_hash)
SELECT 'investigator@netpack.local', 'NetPack Investigator', r.id, true,
       'pbkdf2_sha256$310000$6f4a2c90e13f4b169d62c2a16b6f0e3c$74bea076f1f317ce925b3f1d69229c903e9969e0c1d3a4b9090970ef8d22f420'
FROM roles r
WHERE r.name = 'investigator'
ON CONFLICT (email) DO UPDATE
SET display_name = EXCLUDED.display_name,
    role_id = EXCLUDED.role_id,
    is_active = true,
    password_hash = EXCLUDED.password_hash;

INSERT INTO users (email, display_name, role_id, is_active, password_hash)
SELECT 'auditor@netpack.local', 'NetPack Auditor', r.id, true,
       'pbkdf2_sha256$310000$2b8f1c4d87a650df8c214b3d5e90af11$7dd5aa1d8f89cd4ccc0e3ca0d047d9380919ee5a33bd8de6710f6f8efb2eb1bb'
FROM roles r
WHERE r.name = 'auditor'
ON CONFLICT (email) DO UPDATE
SET display_name = EXCLUDED.display_name,
    role_id = EXCLUDED.role_id,
    is_active = true,
    password_hash = EXCLUDED.password_hash;
