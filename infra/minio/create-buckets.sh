#!/bin/sh
set -eu

mc alias set netpack http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"

mc mb --ignore-existing "netpack/$MINIO_EVIDENCE_BUCKET"
mc mb --ignore-existing "netpack/$MINIO_EXPORTS_BUCKET"

mc version enable "netpack/$MINIO_EVIDENCE_BUCKET"
mc version enable "netpack/$MINIO_EXPORTS_BUCKET"

mc anonymous set none "netpack/$MINIO_EVIDENCE_BUCKET"
mc anonymous set none "netpack/$MINIO_EXPORTS_BUCKET"
