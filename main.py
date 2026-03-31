from flask import Flask, request
import base64
import json
import hashlib
from google.cloud import spanner

app = Flask(__name__)
spanner_client = spanner.Client()
database = spanner_client.instance('iam-guardrails-instance').database('iam-graph-db')


def email_to_id(email):
    """Deterministic INT64 ID from email to avoid database lookups."""
    return int(hashlib.sha256(email.encode()).hexdigest()[:15], 16)


@app.route('/', methods=['POST'])
def handle_pubsub():
    envelope = request.get_json()
    if not envelope:
        return 'Bad request', 400

    pubsub_message = envelope.get('message')
    if not pubsub_message:
        return 'Bad request', 400

    try:
        data = base64.b64decode(pubsub_message.get('data', '')).decode('utf-8')
        log_data = json.loads(data)
    except Exception:
        return 'OK', 200

    proto = log_data.get('protoPayload', {})

    # Cloud Identity group membership events
    metadata = proto.get('metadata', {})
    events = metadata.get('event', [])
    if isinstance(events, dict):
        events = [events]
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict) and event.get('eventName') == 'ADD_GROUP_MEMBER':
                params = {p['name']: p['value'] for p in event.get('parameter', [])}
                user_email = params.get('USER_EMAIL')
                group_email = params.get('GROUP_EMAIL')
                if user_email and group_email:
                    upsert_membership(user_email, group_email)
                    return 'OK', 200

    # SetIamPolicy events
    method = proto.get('methodName', '')
    if 'SetIamPolicy' in method:
        resource_name = proto.get('resourceName', '')
        req = proto.get('request', {})
        policy = req.get('policy', {})
        for binding in policy.get('bindings', []):
            role = binding.get('role', '')
            for member in binding.get('members', []):
                if member.startswith('group:'):
                    group_email = member.replace('group:', '')
                    upsert_permission(group_email, resource_name, role)
        return 'OK', 200

    return 'OK', 200


def upsert_membership(user_email, group_email):
    user_id = email_to_id(user_email)
    group_id = email_to_id(group_email)
    is_sa = 'gserviceaccount.com' in user_email
    is_identity = is_sa or ('.' in user_email.split('@')[0])

    with database.batch() as batch:
        batch.insert_or_update(
            'UserGroups',
            columns=['group_id', 'email', 'name', 'category'],
            values=[[group_id, group_email, group_email.split('@')[0], 'Access']]
        )

        if is_identity:
            identity_type = 'SERVICE_ACCOUNT' if is_sa else 'USER'
            batch.insert_or_update(
                'Identities',
                columns=['identity_id', 'email', 'name', 'type', 'risk_score'],
                values=[[user_id, user_email, user_email.split('@')[0], identity_type, 0.5]]
            )
            batch.insert_or_update(
                'Membership',
                columns=['identity_id', 'group_id'],
                values=[[user_id, group_id]]
            )
        else:
            # nested group
            batch.insert_or_update(
                'UserGroups',
                columns=['group_id', 'email', 'name', 'category'],
                values=[[user_id, user_email, user_email.split('@')[0], 'Access']]
            )
            batch.insert_or_update(
                'GroupNesting',
                columns=['group_id', 'child_group_id'],
                values=[[group_id, user_id]]
            )


def upsert_permission(group_email, resource_name, role):
    group_id = email_to_id(group_email)
    resource_id = email_to_id(resource_name)

    with database.batch() as batch:
        batch.insert_or_update(
            'UserGroups',
            columns=['group_id', 'email', 'name', 'category'],
            values=[[group_id, group_email, group_email.split('@')[0], 'Access']]
        )
        batch.insert_or_update(
            'Resources',
            columns=['resource_id', 'name', 'sensitivity'],
            values=[[resource_id, resource_name, 'High']]
        )
        batch.insert_or_update(
            'Permissions',
            columns=['group_id', 'resource_id', 'role'],
            values=[[group_id, resource_id, role]]
        )


if __name__ == '__main__':
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
