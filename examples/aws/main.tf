# AWS federation for the Trezor sign-in site: an IAM OIDC identity provider,
# a role that trusts it for chosen accounts, and an example S3 bucket the role
# can read and write. See README.md in this folder.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81" # thumbprint_list is optional from 5.81
    }
  }
}

variable "issuer" {
  description = "Sign-in site address (the issuer), e.g. https://owner.github.io/repo"
  type        = string
}

variable "client_id" {
  description = "App ID in config/clients.json with \"cli\": true; becomes the token's aud"
  type        = string
  default     = "aws"
}

variable "subjects" {
  description = "Accounts (the token's sub, as in config/accounts.json) allowed to assume the role"
  type        = list(string)
}

variable "role_name" {
  description = "Name of the role to create"
  type        = string
  default     = "trezor-oidc-example"
}

variable "bucket_name" {
  description = "Name of the example bucket to create"
  type        = string
}

locals {
  # IAM condition keys are the issuer without the scheme, path included.
  issuer_key = trimsuffix(replace(var.issuer, "https://", ""), "/")
}

resource "aws_iam_openid_connect_provider" "trezor" {
  url            = "https://${local.issuer_key}"
  client_id_list = [var.client_id]
}

resource "aws_iam_role" "trezor" {
  name                 = var.role_name
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.trezor.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.issuer_key}:aud" = var.client_id
          "${local.issuer_key}:sub" = var.subjects
        }
      }
    }]
  })
}

resource "aws_s3_bucket" "example" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role_policy" "trezor_s3" {
  role = aws_iam_role.trezor.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = aws_s3_bucket.example.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.example.arn}/*"
      },
    ]
  })
}

output "role_arn" {
  value = aws_iam_role.trezor.arn
}

output "bucket" {
  value = aws_s3_bucket.example.id
}
