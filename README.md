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
      "Action": ["s3:ListAllMyBuckets","s3:GetBucketLocation","s3:GetBucketAcl","s3:GetBucketPolicy","s3:GetBucketEncryption","s3:GetPublicAccessBlock"],
      "Resource": "*" },
    { "Sid": "EC2ReadOnly", "Effect": "Allow",
      "Action": ["ec2:DescribeSecurityGroups"],
      "Resource": "*" }
  ]
}
```

> **Note:** `s3:GetBucketLocation` is required for cross-region bucket scanning. Without it,
> buckets in regions other than the scanner's default region may produce false positives
> (S3-003, S3-004, S3-005) and false negatives (S3-001, S3-002). See [Limitations](#limitations) below.

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

# Export JSON report (table format to file)
npm run scan:json

# JSON format to stdout
node src/cli/index.js --format=json

# Custom region and profile
AWS_REGION=eu-west-1 AWS_PROFILE=audit-role node src/cli/index.js

# Specific services only
node src/cli/index.js --services=iam,s3

# All flags
node src/cli/index.js --services=iam,s3,ec2 --min-severity=HIGH --format=json --output=./reports/scan.json
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | No CRITICAL/HIGH findings and all scans succeeded |
| 1 | Any CRITICAL/HIGH finding, or any scan failed, or invalid arguments |

## Rules

| Rule | Severity | Description |
|---|---|---|
| S3-000 | INFO | Access denied to one or more S3 configuration checks — findings may be incomplete |
| IAM-001 | MEDIUM | Inline policy with wildcard Allow |
| IAM-002 | HIGH | AdministratorAccess or PowerUserAccess attached |
| IAM-003 | HIGH | Trust policy allows AssumeRole by Principal: * |
| S3-001 | CRITICAL | Public ACL (AllUsers / AuthenticatedUsers) |
| S3-002 | CRITICAL | Bucket policy with Principal: * (Allow statement only; Deny statements are not flagged) |
| S3-003 | HIGH | Block Public Access not fully enabled |
| S3-004 | HIGH | No default server-side encryption |
| S3-005 | MEDIUM | No TLS enforcement (aws:SecureTransport) |
| NET-001 | CRITICAL | Admin port (21/22/23/3389/5900) open to internet |
| NET-002 | CRITICAL | All traffic open to internet (protocol -1 or 0-65535) |
| NET-003 | MEDIUM | Non-admin port open to internet (including ICMP/ICMPv6) |

### Access-Denied Handling (S3-000)

When the scanning identity lacks permission to read a bucket's ACL, policy, encryption
configuration, or Block Public Access settings, the scanner emits an **S3-000** INFO finding
for that bucket. Rules that would produce **false positives** on missing data (S3-003,
S3-004, S3-005) are **suppressed** for that bucket. Rules that would produce **false
negatives** on missing data (S3-001, S3-002) are also skipped. This ensures audit outputs
are honest about data gaps rather than producing misleading findings.

## Limitations

- **Cross-region S3 buckets:** The scanner calls `GetBucketLocation` for each bucket and
  routes per-bucket API calls to the correct regional endpoint. If the scanning identity
  lacks `s3:GetBucketLocation`, buckets in other regions will fall back to the default
  region, which may cause `IllegalLocationConstraintException` errors. The scanner treats
  these as "not configured" (potential false positives for S3-003/004/005 and false
  negatives for S3-001/002). Grant `s3:GetBucketLocation` to avoid this.

- **Partial scan failures:** If one service (e.g., IAM) fails due to credentials or
  permissions, the other services (S3, EC2) still run. Partial results are reported.
  The exit code is 1 if any scan failed, even if no CRITICAL/HIGH findings exist.

- **S3-002 and S3-005 check `Allow` and `Deny` statements respectively:** A bucket policy
  with `Principal: *` on a `Deny` statement (e.g., enforcing TLS) is **not** flagged by
  S3-002. Only `Allow` statements with `Principal: *` are flagged.

- **ICMP rules:** Security group rules with ICMP/ICMPv6 protocols open to the internet are
  classified under NET-003 (MEDIUM), with detail text noting the protocol as ICMP rather
  than showing misleading port ranges.

## CI/CD

```yaml
- run: node src/cli/index.js --min-severity=HIGH
```

## JSON Output Schema

Both `--format=json` and `--format=table --output=report.json` produce the same schema:

```json
{
  "generatedAt": "2026-05-12T12:00:00.000Z",
  "totalFindings": 3,
  "summary": { "CRITICAL": 1, "HIGH": 1, "INFO": 1 },
  "findings": [ ... ]
}
```

## Tests

```bash
npm test
```