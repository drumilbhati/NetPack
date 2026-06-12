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
