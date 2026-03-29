# Cloud Security Scanner

A read-only AWS misconfiguration scanner aligned to the **CIS AWS Foundations Benchmark v1.4**.

Detects risky configurations across IAM, S3, and EC2 Security Groups. Produces actionable
remediation guidance in coloured CLI output and machine-readable JSON.

## Ethical & Legal Notice

This tool performs **read-only** AWS API calls only. It never modifies resources.
Run it only against accounts you **own or have explicit written authorisation** to assess.

## Prerequisites

- Node.js 18+
- AWS credentials via the [default provider chain](https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/setting-credentials-node.html)

### Minimum IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "IAMReadOnly", "Effect": "Allow",
      "Action": ["iam:ListRoles","iam:ListAttachedRolePolicies","iam:ListRolePolicies","iam:GetRolePolicy"],
      "Resource": "*" },
    { "Sid": "S3ReadOnly", "Effect": "Allow",
      "Action": ["s3:ListAllMyBuckets","s3:GetBucketAcl","s3:GetBucketPolicy","s3:GetBucketEncryption","s3:GetPublicAccessBlock"],
      "Resource": "*" },
    { "Sid": "EC2ReadOnly", "Effect": "Allow",
      "Action": ["ec2:DescribeSecurityGroups"],
      "Resource": "*" }
  ]
}
```

## Installation

```bash
npm install
```

## Usage

```bash
# Full scan
npm run scan

# HIGH and CRITICAL findings only (CI mode)
npm run scan:critical

# Export JSON report
npm run scan:json

# Custom region and profile
AWS_REGION=eu-west-1 AWS_PROFILE=audit-role node src/cli/index.js

# Specific services only
node src/cli/index.js --services=iam,s3

# All flags
node src/cli/index.js --services=iam,s3,ec2 --min-severity=HIGH --format=json --output=./reports/scan.json
```

## Rules

| Rule | Severity | Description |
|---|---|---|
| IAM-001 | MEDIUM | Inline policy with wildcard Allow |
| IAM-002 | HIGH | AdministratorAccess or PowerUserAccess attached |
| IAM-003 | HIGH | Trust policy allows AssumeRole by Principal: * |
| S3-001 | CRITICAL | Public ACL (AllUsers / AuthenticatedUsers) |
| S3-002 | CRITICAL | Bucket policy with Principal: * |
| S3-003 | HIGH | Block Public Access not fully enabled |
| S3-004 | HIGH | No default server-side encryption |
| S3-005 | MEDIUM | No TLS enforcement (aws:SecureTransport) |
| NET-001 | CRITICAL | Admin port (21/22/23/3389/5900) open to internet |
| NET-002 | CRITICAL | All traffic open to internet (protocol -1 or 0-65535) |
| NET-003 | MEDIUM | Non-admin port open to internet |

## CI/CD

Exit code `1` is set when any CRITICAL or HIGH findings are present:

```yaml
- run: node src/cli/index.js --min-severity=HIGH
```

## Tests

```bash
npm test
```
