#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="86.38.238.123"
REMOTE_PORT="22"
REMOTE_USER="root"
REMOTE_DIR="/root/SploitGPT"

LOCAL_ROOT="/home/cheese/SploitGPT"
LOCAL_DATA="${LOCAL_ROOT}/data"
LOCAL_TRAIN="${LOCAL_DATA}/training"

LOG_FILE="${LOCAL_ROOT}/wait_and_sync.log"

poll_remote_job() {
    ssh -p "${REMOTE_PORT}" "${REMOTE_USER}@${REMOTE_HOST}" \
        "pgrep -f scripts/gen_instructions.py >/dev/null" >/dev/null 2>&1
}

echo "[$(date -Is)] Waiting for remote synthetic generation to finish..." | tee -a "${LOG_FILE}"

while poll_remote_job; do
    echo "[$(date -Is)] Still running on remote...checking again in 60s" | tee -a "${LOG_FILE}"
    sleep 60
done

echo "[$(date -Is)] Remote job finished. Syncing artifacts..." | tee -a "${LOG_FILE}"

mkdir -p "${LOCAL_TRAIN}"

scp -p -P "${REMOTE_PORT}" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/data/training/instructions.jsonl" \
    "${LOCAL_TRAIN}/"

echo "[$(date -Is)] instructions.jsonl copied to ${LOCAL_TRAIN}" | tee -a "${LOG_FILE}"
echo "[$(date -Is)] Done." | tee -a "${LOG_FILE}"
