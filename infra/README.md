# NetPack Infrastructure

This directory provides the local development infrastructure for the NetPack evidence-first MVP.

## Services

- PostgreSQL: system of record for cases, evidence, custody, audit, jobs, alerts, and reports.
- MinIO: S3-compatible object storage for raw PCAP evidence and generated exports.
- Elasticsearch: searchable index for derived flow/session/protocol metadata.
- Kafka: optional streaming profile for the later live-capture phase.

## Start Core Services

```bash
cp .env.example .env
docker compose up -d postgres minio minio-init elasticsearch
```

## Verify Issue 1.2

Register a sample evidence hash in PostgreSQL:

```bash
docker compose exec postgres psql -U netpack -d netpack -c "INSERT INTO cases (case_number, title) VALUES ('CASE-001', 'Sample Case') ON CONFLICT (case_number) DO NOTHING;"
docker compose exec postgres psql -U netpack -d netpack -c "INSERT INTO evidence_files (case_id, original_filename, object_key, sha256, byte_size) SELECT id, 'sample.pcap', 'cases/' || id || '/sample.pcap', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 128 FROM cases WHERE case_number = 'CASE-001' ON CONFLICT (case_id, sha256) DO NOTHING;"
docker compose exec postgres psql -U netpack -d netpack -c "SELECT sha256 FROM evidence_files WHERE sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';"
```

Index sample extracted metadata into Elasticsearch and query by IP:

```bash
python3 ../data_processing/index_metadata.py ../data_processing/sample_metadata.json --query-ip 10.10.1.15
```

## Start Optional Streaming Services

```bash
docker compose --profile streaming up -d
```

## Local URLs

Defaults only. Override these ports in `.env` with `POSTGRES_PORT`, `ELASTICSEARCH_PORT`, `MINIO_API_PORT`, and `MINIO_CONSOLE_PORT`.

- PostgreSQL: `localhost:5432`
- Elasticsearch: `http://localhost:9200`
- MinIO API: `http://localhost:9000`
- MinIO Console: `http://localhost:9001`

Default development credentials are in `.env.example`. Change them for any shared or deployed environment.

## Reset Local Data

```bash
docker compose down -v
```
