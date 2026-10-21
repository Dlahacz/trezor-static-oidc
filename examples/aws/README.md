# AWS access with a Trezor

Use the sign-in site as an OpenID Connect identity provider for AWS IAM. The
command-line tool signs an ID token on your Trezor, AWS STS
(`AssumeRoleWithWebIdentity`) exchanges it for temporary credentials of a role,
and the AWS CLI uses them through `credential_process`.

```
aws s3 ls ──▶ credential_process: trezor-oidc aws-credentials
                 │  1. sign ID token (aud = client ID, sub = account)  ──USB/Bridge──▶ Trezor
                 │  2. AssumeRoleWithWebIdentity(role, token)          ──▶ AWS STS
                 ▼                                                         │ checks the token against
              temporary credentials (cached until 15 min before expiry) ◀──┘ <issuer>/jwks.json
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

## 4. Configure an AWS CLI profile

In `~/.aws/config`:

```ini
[profile trezor]
credential_process = trezor-oidc aws-credentials --issuer https://owner.github.io/repo --client aws --role-arn arn:aws:iam::<account-id>:role/trezor-oidc-example
region = eu-central-1
```

Add `--account <sub>` if the site has more than one account. Then:

```sh
aws --profile trezor sts get-caller-identity
aws --profile trezor s3 ls s3://my-example-bucket/
```

The first command asks you to confirm on the Trezor (and for your PIN or
passphrase if needed, on the terminal). The credentials are cached in
`~/.cache/trezor-oidc/` and reused until 15 minutes before they expire; set
`--duration` (up to the role's `max_session_duration`) for longer sessions,
or `--no-cache` to confirm every time.

### Without credential_process

For a one-off, call STS yourself. `AssumeRoleWithWebIdentity` needs no AWS credentials:

```sh
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<account-id>:role/trezor-oidc-example \
  --role-session-name "trezor-$USER" \
  --web-identity-token "$(trezor-oidc token --issuer "$ISSUER" --client aws)"
```

## Troubleshooting

`trezor-oidc` passes STS errors through:

| Error | Usually means |
|---|---|
| `InvalidIdentityToken: Incorrect token audience` | The app ID isn't in the provider's client ID list |
| `InvalidIdentityToken: Couldn't retrieve verification key` | AWS can't fetch `<issuer>/jwks.json`, or the token's key isn't published yet (wait for the Pages deploy) |
| `AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity` | The role's trust policy doesn't match the token's `aud` or `sub` |
| `ExpiredTokenException` | The token's lifetime (`token_ttl`) passed before the exchange; check the clock |
