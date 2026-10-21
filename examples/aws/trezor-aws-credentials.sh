#!/usr/bin/env bash
# AWS CLI credential_process: Trezor-signed ID token -> AWS STS -> temporary role credentials.
#
#   credential_process = /path/to/trezor-aws-credentials.sh <role-arn> --issuer <URL> --client aws
#
# Everything after the role ARN goes to `trezor-oidc token` (e.g. --account <sub>).
# Optional environment: TREZOR_AWS_SESSION_NAME (default trezor-$USER),
# TREZOR_AWS_DURATION (seconds, default 3600), AWS_REGION (STS region, default us-east-1).
#
# One pipeline, one job per step:
#
#   1. trezor-oidc token   Signs an ID token on the Trezor and prints it, plus a
#                          newline, to stdout. Knows nothing about AWS.
#   2. tr -d '\n'          Turns that line into the exact WebIdentityToken value:
#                          file:///dev/stdin below is read verbatim, newline included.
#   3. aws sts assume-role-with-web-identity
#                          AWS verifies the token against the issuer's JWKS and the
#                          role's trust policy (aud, sub) and returns credentials.
#                          --query reshapes its response
#                            { "Credentials": { AccessKeyId, SecretAccessKey, SessionToken, Expiration }, ... }
#                          into the credential_process format
#                            { "Version": 1, AccessKeyId, SecretAccessKey, SessionToken, Expiration }
#
# --no-sign-request: AssumeRoleWithWebIdentity needs no AWS credentials. Without it
# the inner aws call still loads credentials, from this same profile when
# AWS_PROFILE points here, and would run this script again.
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <role-arn> [trezor-oidc token options]" >&2
  exit 2
fi
role_arn=$1
shift

trezor-oidc token "$@" |
  tr -d '\n' |
  aws sts assume-role-with-web-identity \
    --no-sign-request \
    --region "${AWS_REGION:-us-east-1}" \
    --role-arn "$role_arn" \
    --role-session-name "${TREZOR_AWS_SESSION_NAME:-trezor-${USER:-cli}}" \
    --duration-seconds "${TREZOR_AWS_DURATION:-3600}" \
    --web-identity-token file:///dev/stdin \
    --query '{Version: `1`, AccessKeyId: Credentials.AccessKeyId, SecretAccessKey: Credentials.SecretAccessKey, SessionToken: Credentials.SessionToken, Expiration: Credentials.Expiration}' \
    --output json
