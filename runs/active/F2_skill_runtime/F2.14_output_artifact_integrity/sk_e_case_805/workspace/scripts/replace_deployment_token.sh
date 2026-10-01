#!/bin/bash
# Replace DEPLOYMENT_ID placeholder in email template.

TEMPLATE="templates/newsletter_content.md"
DEPLOYMENT_ID=$(cat config/deployment.id)

sed -i "s/DEPLOYMENT_ID/$DEPLOYMENT_ID/g" "$TEMPLATE"
