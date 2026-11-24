#!/bin/sh
# Deploy the current checkout of Plan B Studio to Cloud Run (task P1-A1). Only Alvi runs this.
#
# What it does: builds the container from the Dockerfile with Cloud Build and rolls it out as
# the service "planb-api", attached to the Cloud SQL instance, with the two secrets and the
# settings from app/config.py passed in as environment variables.
#
# Settings chosen on purpose (see docs/SCALING_PLAYBOOK.md):
#   max 3 instances, 1 vCPU, concurrency 4  -> autoscaling shows up under load
#   min 0 instances                         -> costs nothing when idle (the scaling experiment
#                                              raises it temporarily; every deploy resets it)
#   Cloud SQL connection through a socket   -> no database port is open to the internet
#
# Needs: gcloud signed in, and the secrets planb-jwt-secret and planb-db-passwords to exist in
# Secret Manager (never in git). Usage:  sh scripts/deploy.sh
set -eu

PROJECT="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="europe-west2"
SERVICE="planb-api"
CONN="$PROJECT:$REGION:planb-db"

if [ -z "$PROJECT" ]; then
  echo "No project set. Run: gcloud config set project <PROJECT_ID>" >&2
  exit 1
fi

gcloud run deploy "$SERVICE" \
  --source . \
  --project "$PROJECT" \
  --region "$REGION" \
  --allow-unauthenticated \
  --max-instances 3 \
  --min-instances 0 \
  --concurrency 4 \
  --cpu 1 \
  --memory 512Mi \
  --timeout 60 \
  --cpu-boost \
  --add-cloudsql-instances "$CONN" \
  --set-secrets "JWT_SECRET=planb-jwt-secret:latest,DB_PASSWORDS_JSON=planb-db-passwords:latest" \
  --set-env-vars "DB_NAME=planb,DB_INSTANCE_CONNECTION_NAME=$CONN"

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format='value(status.url)')"
echo "Deployed: $URL"
echo "Health check: $(curl -s -o /dev/null -w '%{http_code}' "$URL/api/v1/healthz")"
