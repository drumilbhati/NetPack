#!/bin/sh
set -eu

if [ -n "${MINIO_EVIDENCE_BUCKET:-}" ] && [ "$MINIO_EVIDENCE_BUCKET" = "${MINIO_EXPORTS_BUCKET:-}" ]; then
  echo "Error: MINIO_EVIDENCE_BUCKET and MINIO_EXPORTS_BUCKET must be different." >&2
  exit 1
fi

mc alias set netpack http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"

mc mb --ignore-existing "netpack/$MINIO_EVIDENCE_BUCKET"
mc mb --ignore-existing "netpack/$MINIO_EXPORTS_BUCKET"

mc version enable "netpack/$MINIO_EVIDENCE_BUCKET"
mc version enable "netpack/$MINIO_EXPORTS_BUCKET"

mc anonymous set none "netpack/$MINIO_EVIDENCE_BUCKET"
mc anonymous set none "netpack/$MINIO_EXPORTS_BUCKET"
