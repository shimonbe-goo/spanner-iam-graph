#!/bin/bash

# Setup script for the IAM access graph pipeline.
# Creates Spanner instance, Pub/Sub topic, logging sink, and deploys Cloud Run.
#
# Prerequisites:
#   - gcloud CLI authenticated with sufficient permissions
#   - Cloud Identity log sharing enabled in Admin Console
#     (Account settings > Legal and compliance > Sharing Options)

PROJECT_ID="YOUR_PROJECT_ID"
REGION="us-central1"
TOPIC_NAME="iam-group-events"
SPANNER_INSTANCE="iam-guardrails-instance"
SPANNER_DATABASE="iam-graph-db"
RUN_SERVICE_NAME="iam-event-processor"

gcloud config set project $PROJECT_ID

# Enable APIs
gcloud services enable \
    pubsub.googleapis.com \
    spanner.googleapis.com \
    run.googleapis.com \
    logging.googleapis.com \
    cloudbuild.googleapis.com

# Spanner
gcloud spanner instances create $SPANNER_INSTANCE \
    --config=regional-$REGION \
    --description="IAM Guardrails Instance" \
    --edition=ENTERPRISE \
    --nodes=1

gcloud spanner databases create $SPANNER_DATABASE \
    --instance=$SPANNER_INSTANCE

# Apply schema
gcloud spanner databases ddl update $SPANNER_DATABASE \
    --instance=$SPANNER_INSTANCE \
    --ddl-file=schema.sql

# Pub/Sub
gcloud pubsub topics create $TOPIC_NAME

# Logging sink
LOG_FILTER='(protoPayload.serviceName="admin.googleapis.com" AND protoPayload.metadata.event.eventName="ADD_GROUP_MEMBER") OR protoPayload.methodName:"SetIamPolicy"'

gcloud logging sinks create iam-logs-sink \
    pubsub.googleapis.com/projects/$PROJECT_ID/topics/$TOPIC_NAME \
    --log-filter="$LOG_FILTER"

# Grant sink permission to publish
SINK_WRITER_IDENTITY=$(gcloud logging sinks describe iam-logs-sink --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding $TOPIC_NAME \
    --member=$SINK_WRITER_IDENTITY \
    --role=roles/pubsub.publisher

# Deploy Cloud Run
gcloud run deploy $RUN_SERVICE_NAME \
    --source . \
    --region $REGION \
    --set-env-vars PROJECT_ID=$PROJECT_ID \
    --allow-unauthenticated

# Create push subscription
RUN_URL=$(gcloud run services describe $RUN_SERVICE_NAME --region $REGION --format='value(status.url)')
gcloud pubsub subscriptions create iam-group-events-sub \
    --topic=$TOPIC_NAME \
    --push-endpoint=$RUN_URL \
    --ack-deadline=60

# Grant Cloud Run SA access to Spanner
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/spanner.databaseUser"

echo "Done. Pipeline is live."
