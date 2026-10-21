# AWS access with a Trezor

Use the sign-in site as an OpenID Connect identity provider for AWS IAM. Two
tools, each with one job, joined by a pipe:

- `trezor-oidc token` signs an ID token on your Trezor and prints it. It knows nothing about AWS.
- `aws sts assume-role-with-web-identity` sends the token to AWS STS, which
  checks it against the issuer's published keys and the role's trust policy,
  and returns temporary credentials for the role.

```
trezor-oidc token ──▶ tr -d '\n' ──▶ aws sts assume-role-with-web-identity ──▶ --query reshape ──▶ credentials
 │ signs on the Trezor   │ token line ->   │ STS verifies the token against          │ STS response ->
 │ aud = app ID          │ exact value     │ <issuer>/jwks.json and the trust policy │ credential_process JSON
 │ sub = account         │                 │ (no AWS credentials needed)             │
```

Below, `ISSUER` is your site address (for example `https://owner.github.io/repo`)
and `ISSUER_KEY` is the same without `https://` (`owner.github.io/repo`).

## 1. Register a command-line app

In `config/clients.json`, add an app with `"cli": true`. Its ID becomes the
token's `aud`, which IAM matches against the provider's client IDs:

```json
{
  "aws": { "name": "AWS", "cli": true }
}
```

The Trezor shows "Sign in to AWS". Apps with `"cli": true` don't need `redirect_uris`.

## 2. Create the identity provider and a role

With Terraform, [`main.tf`](main.tf) creates the identity provider, a role that
trusts it for the accounts you list, and an example S3 bucket for the role:

```sh
terraform init
terraform apply -var issuer="$ISSUER" -var 'subjects=["alice"]' -var bucket_name=my-example-bucket
```

Or with the AWS CLI:

```sh
aws iam create-open-id-connect-provider --url "$ISSUER" --client-id-list aws

cat > trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<account-id>:oidc-provider/$ISSUER_KEY" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "$ISSUER_KEY:aud": "aws",
        "$ISSUER_KEY:sub": ["alice"]
      }
    }
  }]
}
EOF
aws iam create-role --role-name trezor-oidc-example --assume-role-policy-document file://trust.json
# then attach a policy for what the role may do, e.g. aws iam put-role-policy ...
```

Always restrict both `aud` and `sub`. Every registered account can sign tokens
for any app, so `sub` is what limits the role to the people you list.

## 3. Install the command-line tool

Node.js 20 or newer:

```sh
git clone https://github.com/<owner>/<repo>.git trezor-oidc && cd trezor-oidc
npm install   # optional "usb" package for direct USB access
npm link      # puts trezor-oidc on your PATH
```

With Trezor Suite (or Trezor Bridge) running, the tool talks to the device
through it; otherwise it opens the device over USB directly, which needs Suite closed.

Check it prints a token:

```sh
trezor-oidc token --issuer "$ISSUER" --client aws
```

## 4. Exchange the token by hand

The whole flow is one pipeline. `AssumeRoleWithWebIdentity` needs no AWS
credentials, hence `--no-sign-request`:

```sh
trezor-oidc token --issuer "$ISSUER" --client aws \
  | tr -d '\n' \
  | aws sts assume-role-with-web-identity \
      --no-sign-request \
      --role-arn arn:aws:iam::<account-id>:role/trezor-oidc-example \
      --role-session-name "trezor-$USER" \
      --web-identity-token file:///dev/stdin
```

The glue between the two tools:

| Step | Why |
|---|---|
| `tr -d '\n'` | `trezor-oidc` prints the token as a line. `file:///dev/stdin` makes the AWS CLI read the parameter value from the pipe verbatim, and a trailing newline would become part of the token |
| `--web-identity-token file:///dev/stdin` | The token is the request's `WebIdentityToken` |
| `--role-arn`, `--role-session-name` | The rest of the STS request: which role, and a name that shows up in CloudTrail |

STS answers with `Credentials` (`AccessKeyId`, `SecretAccessKey`,
`SessionToken`, `Expiration`) plus the assumed role and the token's subject.

## 5. Configure an AWS CLI profile

[`trezor-aws-credentials.sh`](trezor-aws-credentials.sh) is the same pipeline
with one more step: `--query` reshapes the STS response into the JSON the AWS
CLI expects from a `credential_process`:

```
{ "Credentials": { "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration" }, ... }
   ──▶ { "Version": 1, "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration" }
```

In `~/.aws/config`:

```ini
[profile trezor]
credential_process = /path/to/examples/aws/trezor-aws-credentials.sh arn:aws:iam::<account-id>:role/trezor-oidc-example --issuer https://owner.github.io/repo --client aws
region = eu-central-1
```

Arguments after the role ARN go to `trezor-oidc token` (add `--account <sub>`
if the site has more than one account). Environment: `TREZOR_AWS_DURATION`
(seconds, up to the role's `max_session_duration`, default 3600),
`TREZOR_AWS_SESSION_NAME` (default `trezor-$USER`), `AWS_REGION` (STS region).

```sh
aws --profile trezor sts get-caller-identity
aws --profile trezor s3 ls s3://my-example-bucket/
```

Each command asks you to confirm on the Trezor (and for your PIN or passphrase
if needed, on the terminal). The AWS CLI doesn't cache `credential_process`
results between commands. To confirm once per shell session, load the
credentials into the environment:

```sh
eval "$(aws configure export-credentials --profile trezor --format env)"
aws s3 ls s3://my-example-bucket/   # no Trezor prompt until they expire
```

The script passes `--no-sign-request` to its inner `aws` call for a second
reason: without it, that call would load credentials from the same profile
(when `AWS_PROFILE=trezor`) and run the script again.

## Troubleshooting

STS errors appear in the AWS CLI's output:

| Error | Usually means |
|---|---|
| `InvalidIdentityToken: Incorrect token audience` | The app ID isn't in the provider's client ID list |
| `InvalidIdentityToken: Couldn't retrieve verification key` | AWS can't fetch `<issuer>/jwks.json`, or the token's key isn't published yet (wait for the Pages deploy) |
| `AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity` | The role's trust policy doesn't match the token's `aud` or `sub` |
| `ExpiredTokenException` | The token's lifetime (`token_ttl`) passed before the exchange; check the clock |
