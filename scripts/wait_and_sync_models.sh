#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="86.38.238.123"
REMOTE_PORT="22"
REMOTE_USER="root"
REMOTE_DIR="/root/SploitGPT"

LOCAL_ROOT="/home/cheese/SploitGPT"
LOCAL_MODELS="${LOCAL_ROOT}/models"

LOG_FILE="${LOCAL_ROOT}/wait_and_sync_models.log"

poll_remote_job() {
    ssh -p "${REMOTE_PORT}" "${REMOTE_USER}@${REMOTE_HOST}" \
        "pgrep -f 'python -m sploitgpt.training.finetune' >/dev/null" >/dev/null 2>&1
}

echo "[$(date -Is)] Waiting for remote fine-tune job..." | tee -a "${LOG_FILE}"

while poll_remote_job; do
    echo "[$(date -Is)] Fine-tune still running...next check in 60s" | tee -a "${LOG_FILE}"
    sleep 60
done

echo "[$(date -Is)] Fine-tune complete. Syncing models..." | tee -a "${LOG_FILE}"

mkdir -p "${LOCAL_MODELS}"

rsync -az -e "ssh -p ${REMOTE_PORT}" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/models/" \
    "${LOCAL_MODELS}/"

scp -p -P "${REMOTE_PORT}" \
    "${REMOTE_USER}@${REMOTE_HOST}:/root/finetune.log" \
    "${LOCAL_ROOT}/finetune.log"

echo "[$(date -Is)] Models and logs synced to ${LOCAL_MODELS}" | tee -a "${LOG_FILE}"
