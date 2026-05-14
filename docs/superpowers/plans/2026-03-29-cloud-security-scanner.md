# Cloud Security Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only AWS misconfiguration scanner that detects risky IAM, S3, and EC2 Security Group configurations, assigns CIS-aligned severity scores, and outputs actionable remediation guidance via CLI.

**Architecture:** Eight focused modules in a pipeline pattern: three scanners fetch raw AWS resources (paginated), a stateless rule engine converts resources to findings, a severity enricher annotates findings with impact/remediation, and a reporter handles CLI output and JSON export. The CLI entry point orchestrates the pipeline and manages exit codes for CI/CD integration.

**Tech Stack:** Node.js 18+, AWS SDK v3 (`@aws-sdk/client-iam`, `@aws-sdk/client-s3`, `@aws-sdk/client-ec2`), Jest (unit tests), no other runtime dependencies.

---

## File Map

| File | Responsibility |
|---|---|
| `src/config/aws.js` | AWS SDK client factory — reads region from env, exposes singleton clients |
| `src/scanners/iamScanner.js` | Paginated IAM role scan with trust policy + attached + inline policies |
| `src/scanners/s3Scanner.js` | Per-bucket ACL, policy, encryption, Block Public Access checks |
| `src/scanners/ec2Scanner.js` | Paginated security group scan including IPv6 ranges |
| `src/analysis/rules.js` | Stateless rule functions returning `{ ruleId, resource, detail }` findings |
| `src/analysis/severities.js` | Severity map, ordering, enrichment, and min-severity filter |
| `src/utils/reporter.js` | ANSI-coloured terminal output + optional JSON file export |
| `src/cli/index.js` | CLI arg parser, pipeline orchestration, exit codes |
| `package.json` | Deps, engines, npm scripts |
| `tests/analysis/rules.test.js` | Unit tests for all rule functions |
| `tests/analysis/severities.test.js` | Unit tests for enrichment and severity filtering |
| `tests/utils/reporter.test.js` | Unit tests for report formatting and JSON export |
| `tests/cli/parseArgs.test.js` | Unit tests for the CLI arg parser |

---

## Task 1: Project scaffold and package.json

**Files:**
- Create: `package.json`
- Create: `.gitignore`

- [ ] **Step 1: Initialise the project directory**

```bash
cd "/Users/main/Security Apps/cloud-security"
git init
```

- [ ] **Step 2: Create package.json**

```json
{
  "name": "cloud-security",
  "version": "1.0.0",
  "description": "Read-only AWS misconfiguration scanner aligned to CIS AWS Foundations Benchmark v1.4",
  "main": "src/cli/index.js",
  "scripts": {
    "scan":          "node src/cli/index.js",
    "scan:critical": "node src/cli/index.js --min-severity=HIGH",
    "scan:json":     "node src/cli/index.js --format=table --output=./reports/latest.json",
    "test":          "jest --coverage"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {
    "@aws-sdk/client-ec2": "^3.0.0",
    "@aws-sdk/client-iam": "^3.0.0",
    "@aws-sdk/client-s3":  "^3.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  },
  "license": "MIT"
}
```

- [ ] **Step 3: Create .gitignore**

```
node_modules/
reports/
.env
*.json.bak
```

- [ ] **Step 4: Install dependencies**

```bash
npm install
```

Expected: `node_modules/` created, no errors.

- [ ] **Step 5: Create directory structure**

```bash
mkdir -p src/config src/scanners src/analysis src/utils src/cli tests/analysis tests/utils tests/cli reports
```

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json .gitignore
git commit -m "chore: initialise project, install deps"
```

---

## Task 2: AWS client factory

**Files:**
- Create: `src/config/aws.js`

- [ ] **Step 1: Write `src/config/aws.js`**

```js
// src/config/aws.js
// AWS SDK client factory. Credentials resolved via default provider chain — never hardcoded.
// Chain order: AWS_ACCESS_KEY_ID/SECRET → ~/.aws/credentials → IAM role → SSO session.

const { S3Client }  = require("@aws-sdk/client-s3");
const { IAMClient } = require("@aws-sdk/client-iam");
const { EC2Client } = require("@aws-sdk/client-ec2");

const REGION = process.env.AWS_REGION || "us-east-1";
const clientConfig = { region: REGION };

const s3  = new S3Client(clientConfig);
const iam = new IAMClient(clientConfig);
const ec2 = new EC2Client(clientConfig);

module.exports = { s3, iam, ec2, REGION };
```

- [ ] **Step 2: Verify the file loads without error**

```bash
node -e "const c = require('./src/config/aws'); console.log('region:', c.REGION);"
```

Expected output: `region: us-east-1` (or whatever `AWS_REGION` is set to).

- [ ] **Step 3: Commit**

```bash
git add src/config/aws.js
git commit -m "feat: add AWS SDK client factory with env-driven region"
```

---

## Task 3: Severity model

**Files:**
- Create: `src/analysis/severities.js`
- Create: `tests/analysis/severities.test.js`

- [ ] **Step 1: Write the failing tests**

```js
// tests/analysis/severities.test.js
const {
  SEVERITY,
  SEVERITY_ORDER,
  enrichFindings,
  meetsMinSeverity,
} = require("../../src/analysis/severities");

describe("SEVERITY_ORDER", () => {
  it("orders severities from least to most severe", () => {
    expect(SEVERITY_ORDER).toEqual(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
  });
});

describe("enrichFindings", () => {
  it("enriches a known rule ID with severity, impact, and remediation", () => {
    const raw = [{ ruleId: "NET-001", resource: "ec2:sg/sg-123", detail: "Port 22 open" }];
    const enriched = enrichFindings(raw);
    expect(enriched[0].severity).toBe("CRITICAL");
    expect(enriched[0].impact).toBeDefined();
    expect(enriched[0].remediation).toBeDefined();
    expect(enriched[0].ruleId).toBe("NET-001");
    expect(enriched[0].resource).toBe("ec2:sg/sg-123");
    expect(enriched[0].detail).toBe("Port 22 open");
  });

  it("falls back to LOW for an unknown rule ID", () => {
    const raw = [{ ruleId: "UNKNOWN-999", resource: "foo", detail: "bar" }];
    const enriched = enrichFindings(raw);
    expect(enriched[0].severity).toBe("LOW");
  });

  it("returns an empty array for empty input", () => {
    expect(enrichFindings([])).toEqual([]);
  });
});

describe("meetsMinSeverity", () => {
  it("returns true when finding severity equals min severity", () => {
    expect(meetsMinSeverity({ severity: "HIGH" }, "HIGH")).toBe(true);
  });

  it("returns true when finding severity is above min severity", () => {
    expect(meetsMinSeverity({ severity: "CRITICAL" }, "HIGH")).toBe(true);
  });

  it("returns false when finding severity is below min severity", () => {
    expect(meetsMinSeverity({ severity: "LOW" }, "HIGH")).toBe(false);
  });

  it("returns true for INFO when min is INFO", () => {
    expect(meetsMinSeverity({ severity: "INFO" }, "INFO")).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npx jest tests/analysis/severities.test.js --no-coverage
```

Expected: FAIL — `Cannot find module '../../src/analysis/severities'`

- [ ] **Step 3: Write `src/analysis/severities.js`**

```js
// src/analysis/severities.js
// Maps rule IDs to severity, impact, and remediation. Kept separate from rule
// logic so severity thresholds can be tuned without touching scan logic.

const SEVERITY = {
  INFO:     "INFO",
  LOW:      "LOW",
  MEDIUM:   "MEDIUM",
  HIGH:     "HIGH",
  CRITICAL: "CRITICAL",
};

// Ordered least → most severe. Used by meetsMinSeverity for threshold filtering.
const SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const RULE_METADATA = {
  "IAM-001": {
    severity:    SEVERITY.MEDIUM,
    impact:      "Over-broad permissions increase blast radius if this role is compromised",
    remediation: "Replace wildcard actions with the explicit set of API calls the role requires (least-privilege)",
  },
  "IAM-002": {
    severity:    SEVERITY.HIGH,
    impact:      "Role has unrestricted access to all AWS services and all resources",
    remediation: "Detach AdministratorAccess; replace with a custom scoped policy for the role's specific function",
  },
  "IAM-003": {
    severity:    SEVERITY.HIGH,
    impact:      "Any AWS principal or unintended party can assume this role",
    remediation: "Restrict Principal to specific account IDs, role ARNs, or services; add a Condition block where possible",
  },
  "S3-001": {
    severity:    SEVERITY.CRITICAL,
    impact:      "Objects are readable or writable by anyone on the internet via ACLs",
    remediation: "Remove AllUsers/AuthenticatedUsers ACL grants; enable S3 Block Public Access at bucket and account level",
  },
  "S3-002": {
    severity:    SEVERITY.CRITICAL,
    impact:      "Bucket policy exposes data to the public internet via Principal: *",
    remediation: "Replace Principal: * with specific IAM principals; enable S3 Block Public Access",
  },
  "S3-003": {
    severity:    SEVERITY.HIGH,
    impact:      "A single misconfigured ACL or policy can expose this bucket publicly at any time",
    remediation: "Enable all four Block Public Access flags at both bucket and account level (AWS console or CLI)",
  },
  "S3-004": {
    severity:    SEVERITY.HIGH,
    impact:      "Data at rest is unencrypted; physical or logical media access could expose objects",
    remediation: "Enable default encryption: SSE-S3 (AES-256) as minimum; use SSE-KMS for sensitive or regulated data",
  },
  "S3-005": {
    severity:    SEVERITY.MEDIUM,
    impact:      "Clients can transmit data over plain HTTP — credentials and data are exposed in transit",
    remediation: "Add a bucket policy Deny statement: Effect=Deny, Action=s3:*, Condition: {Bool: {aws:SecureTransport: false}}",
  },
  "NET-001": {
    severity:    SEVERITY.CRITICAL,
    impact:      "Admin service is exposed to the entire internet — high brute-force and direct attack risk",
    remediation: "Restrict to a known static IP range, or remove direct access and use AWS Systems Manager Session Manager",
  },
  "NET-002": {
    severity:    SEVERITY.CRITICAL,
    impact:      "Maximum attack surface — all traffic from the internet is permitted into this security group",
    remediation: "Replace 0.0.0.0/0 and ::/0 rules with the minimum required ports and source CIDRs",
  },
  "NET-003": {
    severity:    SEVERITY.MEDIUM,
    impact:      "Unnecessarily wide internet ingress increases exposure to scanning and targeted attacks",
    remediation: "Narrow CIDR to known prefixes, or use security group references for intra-VPC traffic",
  },
};

function enrichFindings(findings) {
  return findings.map((f) => {
    const meta = RULE_METADATA[f.ruleId] || {
      severity:    SEVERITY.LOW,
      impact:      "Review this configuration manually",
      remediation: "Refer to AWS documentation and the CIS AWS Foundations Benchmark",
    };
    return { ...f, ...meta };
  });
}

function meetsMinSeverity(finding, minSeverity) {
  return (
    SEVERITY_ORDER.indexOf(finding.severity) >=
    SEVERITY_ORDER.indexOf(minSeverity)
  );
}

module.exports = { SEVERITY, SEVERITY_ORDER, RULE_METADATA, enrichFindings, meetsMinSeverity };
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npx jest tests/analysis/severities.test.js --no-coverage
```

Expected: PASS — all 7 tests green.

- [ ] **Step 5: Commit**

```bash
git add src/analysis/severities.js tests/analysis/severities.test.js
git commit -m "feat: add severity model with enrichment and min-severity filter"
```

---

## Task 4: Analysis rule engine

**Files:**
- Create: `src/analysis/rules.js`
- Create: `tests/analysis/rules.test.js`

- [ ] **Step 1: Write the failing tests**

```js
// tests/analysis/rules.test.js
const { analyzeIAM, analyzeS3, analyzeSecurityGroups } = require("../../src/analysis/rules");

// ── IAM ──────────────────────────────────────────────────────────────────────

describe("analyzeIAM", () => {
  it("flags IAM-001 for an inline policy with wildcard action", () => {
    const roles = [{
      name: "app-role",
      trustPolicy: null,
      attachedPolicies: [],
      inlinePolicies: [{
        name: "overly-broad",
        document: {
          Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }],
        },
      }],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-001")).toBe(true);
  });

  it("does NOT flag IAM-001 for a Deny statement with wildcard (Deny is a control, not a vuln)", () => {
    const roles = [{
      name: "safe-role",
      trustPolicy: null,
      attachedPolicies: [],
      inlinePolicies: [{
        name: "deny-policy",
        document: {
          Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }],
        },
      }],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-001")).toBe(false);
  });

  it("flags IAM-002 for AdministratorAccess attached policy", () => {
    const roles = [{
      name: "ci-deploy",
      trustPolicy: null,
      attachedPolicies: [{ PolicyName: "AdministratorAccess" }],
      inlinePolicies: [],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-002")).toBe(true);
  });

  it("flags IAM-002 for PowerUserAccess attached policy", () => {
    const roles = [{
      name: "ci-deploy",
      trustPolicy: null,
      attachedPolicies: [{ PolicyName: "PowerUserAccess" }],
      inlinePolicies: [],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-002")).toBe(true);
  });

  it("flags IAM-003 for a trust policy with Principal: *", () => {
    const roles = [{
      name: "public-role",
      trustPolicy: {
        Statement: [{
          Effect: "Allow",
          Principal: "*",
          Action: "sts:AssumeRole",
        }],
      },
      attachedPolicies: [],
      inlinePolicies: [],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-003")).toBe(true);
  });

  it("returns empty array for a clean role", () => {
    const roles = [{
      name: "clean-role",
      trustPolicy: {
        Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }],
      },
      attachedPolicies: [{ PolicyName: "AmazonS3ReadOnlyAccess" }],
      inlinePolicies: [],
    }];
    expect(analyzeIAM(roles)).toEqual([]);
  });
});

// ── S3 ───────────────────────────────────────────────────────────────────────

describe("analyzeS3", () => {
  function makeCleanBucket(name = "my-bucket") {
    return {
      name,
      acl: {
        Grants: [
          { Grantee: { Type: "CanonicalUser", ID: "abc123" }, Permission: "FULL_CONTROL" },
        ],
      },
      policyText: JSON.stringify({
        Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::123456789012:root" }, Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" }],
      }),
      encryption: { ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } }] } },
      publicAccessBlock: {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
      },
    };
  }

  it("returns empty array for a clean bucket", () => {
    expect(analyzeS3([makeCleanBucket()])).toEqual([]);
  });

  it("flags S3-001 when ACL grants READ to AllUsers", () => {
    const bucket = makeCleanBucket();
    bucket.acl.Grants.push({
      Grantee: { Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers" },
      Permission: "READ",
    });
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-001")).toBe(true);
  });

  it("flags S3-002 when bucket policy has Principal: *", () => {
    const bucket = makeCleanBucket();
    bucket.policyText = JSON.stringify({
      Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" }],
    });
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-002")).toBe(true);
  });

  it("flags S3-003 when Block Public Access is not fully enabled", () => {
    const bucket = makeCleanBucket();
    bucket.publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls = false;
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-003")).toBe(true);
  });

  it("flags S3-003 when publicAccessBlock is null (not configured)", () => {
    const bucket = makeCleanBucket();
    bucket.publicAccessBlock = null;
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-003")).toBe(true);
  });

  it("flags S3-004 when encryption is null (not configured)", () => {
    const bucket = makeCleanBucket();
    bucket.encryption = null;
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-004")).toBe(true);
  });

  it("flags S3-005 when bucket policy has no SecureTransport deny", () => {
    const bucket = makeCleanBucket();
    // Policy exists but has no Deny + aws:SecureTransport condition
    bucket.policyText = JSON.stringify({
      Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::123:root" }, Action: "s3:GetObject" }],
    });
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-005")).toBe(true);
  });

  it("flags S3-005 when policyText is null (no policy at all)", () => {
    const bucket = makeCleanBucket();
    bucket.policyText = null;
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-005")).toBe(true);
  });
});

// ── EC2 / Security Groups ────────────────────────────────────────────────────

describe("analyzeSecurityGroups", () => {
  function makeSG(overrides = {}) {
    return {
      GroupId: "sg-abc123",
      GroupName: "test-sg",
      IpPermissions: [],
      ...overrides,
    };
  }

  it("returns empty array for a security group with no public rules", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "tcp", FromPort: 443, ToPort: 443,
        IpRanges: [{ CidrIp: "10.0.0.0/8" }],
        Ipv6Ranges: [],
      }],
    });
    expect(analyzeSecurityGroups([sg])).toEqual([]);
  });

  it("flags NET-001 for SSH (22) open to 0.0.0.0/0", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "tcp", FromPort: 22, ToPort: 22,
        IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        Ipv6Ranges: [],
      }],
    });
    const findings = analyzeSecurityGroups([sg]);
    expect(findings.some((f) => f.ruleId === "NET-001")).toBe(true);
  });

  it("flags NET-001 for RDP (3389) open to ::/0 (IPv6)", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "tcp", FromPort: 3389, ToPort: 3389,
        IpRanges: [],
        Ipv6Ranges: [{ CidrIpv6: "::/0" }],
      }],
    });
    const findings = analyzeSecurityGroups([sg]);
    expect(findings.some((f) => f.ruleId === "NET-001")).toBe(true);
  });

  it("flags NET-001 for Telnet (23), FTP (21), and VNC (5900)", () => {
    for (const port of [21, 23, 5900]) {
      const sg = makeSG({
        IpPermissions: [{
          IpProtocol: "tcp", FromPort: port, ToPort: port,
          IpRanges: [{ CidrIp: "0.0.0.0/0" }],
          Ipv6Ranges: [],
        }],
      });
      const findings = analyzeSecurityGroups([sg]);
      expect(findings.some((f) => f.ruleId === "NET-001")).toBe(true);
    }
  });

  it("flags NET-002 for protocol -1 (all traffic) open to 0.0.0.0/0", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "-1", FromPort: null, ToPort: null,
        IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        Ipv6Ranges: [],
      }],
    });
    const findings = analyzeSecurityGroups([sg]);
    expect(findings.some((f) => f.ruleId === "NET-002")).toBe(true);
  });

  it("flags NET-002 for full port range (0-65535) open to 0.0.0.0/0", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "tcp", FromPort: 0, ToPort: 65535,
        IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        Ipv6Ranges: [],
      }],
    });
    const findings = analyzeSecurityGroups([sg]);
    expect(findings.some((f) => f.ruleId === "NET-002")).toBe(true);
  });

  it("flags NET-003 for a non-admin port open to 0.0.0.0/0", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "tcp", FromPort: 8080, ToPort: 8080,
        IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        Ipv6Ranges: [],
      }],
    });
    const findings = analyzeSecurityGroups([sg]);
    expect(findings.some((f) => f.ruleId === "NET-003")).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npx jest tests/analysis/rules.test.js --no-coverage
```

Expected: FAIL — `Cannot find module '../../src/analysis/rules'`

- [ ] **Step 3: Write `src/analysis/rules.js`**

```js
// src/analysis/rules.js
// Stateless rule functions. Each accepts normalised resource data and returns
// findings: { ruleId, resource, detail }.
// Severity/impact/remediation are NOT assigned here — that belongs to severities.js.

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Returns true if any Allow statement in a policy document uses a wildcard
 * for Action or Resource. Deny statements are intentionally excluded — they
 * are security controls, not vulnerabilities.
 */
function hasWildcardAllow(document) {
  if (!document?.Statement) return false;
  for (const stmt of document.Statement) {
    if (stmt.Effect !== "Allow") continue;
    const actions   = [].concat(stmt.Action   || []);
    const resources = [].concat(stmt.Resource || []);
    if (actions.includes("*") || resources.includes("*")) return true;
  }
  return false;
}

/**
 * Returns true if a trust policy grants AssumeRole to Principal: "*".
 */
function hasPublicTrustPrincipal(trustPolicy) {
  if (!trustPolicy?.Statement) return false;
  for (const stmt of trustPolicy.Statement) {
    if (stmt.Effect !== "Allow") continue;
    if (stmt.Principal === "*") return true;
    if (typeof stmt.Principal === "object" && stmt.Principal.AWS === "*") return true;
  }
  return false;
}

// ── IAM ──────────────────────────────────────────────────────────────────────

const OVER_PERMISSIVE_POLICIES = new Set(["AdministratorAccess", "PowerUserAccess"]);

function analyzeIAM(roles) {
  const findings = [];

  for (const role of roles) {
    const resource = `iam:role/${role.name}`;

    // IAM-001: wildcard Allow in inline policies
    for (const policy of role.inlinePolicies || []) {
      if (hasWildcardAllow(policy.document)) {
        const wildcardActions = [].concat(policy.document.Statement || [])
          .filter((s) => s.Effect === "Allow")
          .flatMap((s) => [].concat(s.Action || []))
          .filter((a) => a === "*");

        const wildcardResources = [].concat(policy.document.Statement || [])
          .filter((s) => s.Effect === "Allow")
          .flatMap((s) => [].concat(s.Resource || []))
          .filter((r) => r === "*");

        const example = wildcardActions.length
          ? `Inline policy "${policy.name}" allows Action: *`
          : `Inline policy "${policy.name}" allows Resource: *`;

        findings.push({ ruleId: "IAM-001", resource, detail: example });
      }
    }

    // IAM-002: over-permissive managed policy
    for (const policy of role.attachedPolicies || []) {
      if (OVER_PERMISSIVE_POLICIES.has(policy.PolicyName)) {
        findings.push({
          ruleId:   "IAM-002",
          resource,
          detail:   `Managed policy "${policy.PolicyName}" is attached`,
        });
      }
    }

    // IAM-003: public trust principal
    if (hasPublicTrustPrincipal(role.trustPolicy)) {
      findings.push({
        ruleId:   "IAM-003",
        resource,
        detail:   `Trust policy allows AssumeRole by Principal: * (anyone can assume this role)`,
      });
    }
  }

  return findings;
}

// ── S3 ───────────────────────────────────────────────────────────────────────

const PUBLIC_GRANTEE_URIS = new Set([
  "http://acs.amazonaws.com/groups/global/AllUsers",
  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
]);

const PUBLIC_PERMISSIONS = new Set(["READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"]);

function analyzeS3(buckets) {
  const findings = [];

  for (const bucket of buckets) {
    const resource = `s3::${bucket.name}`;

    // S3-001: Public ACL
    if (bucket.acl?.Grants) {
      for (const grant of bucket.acl.Grants) {
        if (
          grant.Grantee?.Type === "Group" &&
          PUBLIC_GRANTEE_URIS.has(grant.Grantee.URI) &&
          PUBLIC_PERMISSIONS.has(grant.Permission)
        ) {
          findings.push({
            ruleId:   "S3-001",
            resource,
            detail:   `ACL grants ${grant.Permission} to ${grant.Grantee.URI.split("/").pop()} (public group)`,
          });
        }
      }
    }

    // S3-002: Public bucket policy (Principal: *)
    if (bucket.policyText) {
      let policy;
      try { policy = JSON.parse(bucket.policyText); } catch (_) { policy = null; }
      if (policy?.Statement) {
        for (const stmt of policy.Statement) {
          if (
            stmt.Effect === "Allow" &&
            (stmt.Principal === "*" || stmt.Principal?.AWS === "*")
          ) {
            findings.push({
              ruleId:   "S3-002",
              resource,
              detail:   `Bucket policy allows Principal: * on an Allow statement`,
            });
            break; // one finding per bucket is enough for S3-002
          }
        }
      }
    }

    // S3-003: Block Public Access not fully enabled
    const bpa = bucket.publicAccessBlock?.PublicAccessBlockConfiguration;
    if (
      !bpa ||
      !bpa.BlockPublicAcls ||
      !bpa.BlockPublicPolicy ||
      !bpa.IgnorePublicAcls ||
      !bpa.RestrictPublicBuckets
    ) {
      findings.push({
        ruleId:   "S3-003",
        resource,
        detail:   "Block Public Access is not fully enabled on this bucket",
      });
    }

    // S3-004: No default encryption
    const encRules = bucket.encryption?.ServerSideEncryptionConfiguration?.Rules;
    if (!encRules || encRules.length === 0) {
      findings.push({
        ruleId:   "S3-004",
        resource,
        detail:   "No default server-side encryption rule is configured",
      });
    }

    // S3-005: TLS not enforced (no Deny on aws:SecureTransport = false)
    const hasSecureTransportDeny = (() => {
      if (!bucket.policyText) return false;
      let policy;
      try { policy = JSON.parse(bucket.policyText); } catch (_) { return false; }
      if (!policy?.Statement) return false;
      return policy.Statement.some((stmt) => {
        if (stmt.Effect !== "Deny") return false;
        const condition = stmt.Condition;
        return (
          condition?.Bool?.["aws:SecureTransport"] === "false" ||
          condition?.Bool?.["aws:SecureTransport"] === false
        );
      });
    })();

    if (!hasSecureTransportDeny) {
      findings.push({
        ruleId:   "S3-005",
        resource,
        detail:   "No Deny statement enforcing aws:SecureTransport=false found in bucket policy",
      });
    }
  }

  return findings;
}

// ── EC2 Security Groups ───────────────────────────────────────────────────────

// Ports that provide direct administrative access — highest risk when internet-exposed.
const ADMIN_PORTS = new Set([21, 22, 23, 3389, 5900]);

/**
 * Classify a single inbound rule (one CIDR on one permission) into a finding.
 * Called for both IPv4 (0.0.0.0/0) and IPv6 (::/0) open-internet CIDRs.
 */
function classifyNetworkFinding(sgId, sgName, fromPort, toPort, protocol, cidr, findings) {
  const label = `SG "${sgName}" (${sgId})`;

  // NET-002: All traffic rule (protocol -1 = all, or full port range)
  if (protocol === "-1") {
    findings.push({
      ruleId:   "NET-002",
      resource: `ec2:security-group/${sgId}`,
      detail:   `All traffic (protocol -1) open to ${cidr} on ${label}`,
    });
    return;
  }

  if (fromPort === 0 && toPort === 65535) {
    findings.push({
      ruleId:   "NET-002",
      resource: `ec2:security-group/${sgId}`,
      detail:   `All TCP/UDP ports (0-65535) open to ${cidr} on ${label}`,
    });
    return;
  }

  // NET-001: Admin port open to internet
  if (ADMIN_PORTS.has(fromPort)) {
    findings.push({
      ruleId:   "NET-001",
      resource: `ec2:security-group/${sgId}`,
      detail:   `Admin port ${fromPort} open to ${cidr} on ${label}`,
    });
    return;
  }

  // NET-003: Any other port open to internet
  findings.push({
    ruleId:   "NET-003",
    resource: `ec2:security-group/${sgId}`,
    detail:   `Port range ${fromPort}-${toPort} open to ${cidr} on ${label}`,
  });
}

function analyzeSecurityGroups(groups) {
  const findings = [];

  for (const sg of groups) {
    const sgId   = sg.GroupId;
    const sgName = sg.GroupName || sgId;

    for (const perm of sg.IpPermissions || []) {
      const { FromPort: from, ToPort: to, IpProtocol: proto } = perm;

      for (const range of perm.IpRanges || []) {
        if (range.CidrIp === "0.0.0.0/0") {
          classifyNetworkFinding(sgId, sgName, from, to, proto, "0.0.0.0/0", findings);
        }
      }

      for (const range of perm.Ipv6Ranges || []) {
        if (range.CidrIpv6 === "::/0") {
          classifyNetworkFinding(sgId, sgName, from, to, proto, "::/0", findings);
        }
      }
    }
  }

  return findings;
}

module.exports = { analyzeIAM, analyzeS3, analyzeSecurityGroups };
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npx jest tests/analysis/rules.test.js --no-coverage
```

Expected: PASS — all tests green.

- [ ] **Step 5: Commit**

```bash
git add src/analysis/rules.js tests/analysis/rules.test.js
git commit -m "feat: add stateless rule engine for IAM, S3, and EC2 security groups"
```

---

## Task 5: Reporter

**Files:**
- Create: `src/utils/reporter.js`
- Create: `tests/utils/reporter.test.js`

- [ ] **Step 1: Write the failing tests**

```js
// tests/utils/reporter.test.js
const fs   = require("fs");
const path = require("path");
const os   = require("os");

// Capture stdout without mocking the entire console
let output = "";
const originalLog = console.log;
const originalError = console.error;
beforeEach(() => { output = ""; console.log = (...args) => { output += args.join(" ") + "\n"; }; });
afterEach(() => { console.log = originalLog; console.error = originalError; });

const { reportFindings } = require("../../src/utils/reporter");

function makeFindings() {
  return [
    {
      ruleId:      "NET-001",
      resource:    "ec2:security-group/sg-123",
      detail:      "Port 22 open to 0.0.0.0/0",
      severity:    "CRITICAL",
      impact:      "SSH exposed to internet",
      remediation: "Use SSM Session Manager",
    },
    {
      ruleId:      "IAM-001",
      resource:    "iam:role/app-role",
      detail:      'Inline policy allows Action: *',
      severity:    "MEDIUM",
      impact:      "Blast radius increased",
      remediation: "Use least-privilege",
    },
  ];
}

describe("reportFindings", () => {
  it("prints a 'no findings' message for empty findings", () => {
    reportFindings([]);
    expect(output).toMatch(/no findings/i);
  });

  it("prints each finding's ruleId, detail, impact, and remediation", () => {
    reportFindings(makeFindings());
    expect(output).toContain("NET-001");
    expect(output).toContain("Port 22 open to 0.0.0.0/0");
    expect(output).toContain("SSH exposed to internet");
    expect(output).toContain("Use SSM Session Manager");
  });

  it("prints a SUMMARY line with correct counts", () => {
    reportFindings(makeFindings());
    expect(output).toMatch(/SUMMARY/);
    expect(output).toMatch(/CRITICAL.*1/);
    expect(output).toMatch(/MEDIUM.*1/);
  });

  it("writes a JSON report file when outputPath is provided", () => {
    const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), "cloud-sec-test-"));
    const outFile = path.join(tmpDir, "report.json");
    reportFindings(makeFindings(), { outputPath: outFile });

    const written = JSON.parse(fs.readFileSync(outFile, "utf8"));
    expect(written.totalFindings).toBe(2);
    expect(written.findings).toHaveLength(2);
    expect(written.generatedAt).toBeDefined();

    fs.rmSync(tmpDir, { recursive: true });
  });

  it("does not crash when the output directory does not exist yet", () => {
    const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), "cloud-sec-test-"));
    const outFile = path.join(tmpDir, "nested", "deep", "report.json");
    expect(() => reportFindings(makeFindings(), { outputPath: outFile })).not.toThrow();
    fs.rmSync(tmpDir, { recursive: true });
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npx jest tests/utils/reporter.test.js --no-coverage
```

Expected: FAIL — `Cannot find module '../../src/utils/reporter'`

- [ ] **Step 3: Write `src/utils/reporter.js`**

```js
// src/utils/reporter.js
// Terminal output (ANSI colours, summary block) + optional JSON file export.
// ANSI codes are stripped automatically when stdout is not a TTY (CI, pipes).

const fs   = require("fs");
const path = require("path");

const isTTY = process.stdout.isTTY;
const C = {
  reset:   isTTY ? "\x1b[0m"  : "",
  bold:    isTTY ? "\x1b[1m"  : "",
  dim:     isTTY ? "\x1b[2m"  : "",
  red:     isTTY ? "\x1b[31m" : "",
  yellow:  isTTY ? "\x1b[33m" : "",
  cyan:    isTTY ? "\x1b[36m" : "",
  green:   isTTY ? "\x1b[32m" : "",
};

const SEVERITY_COLOR = {
  CRITICAL: C.red  + C.bold,
  HIGH:     C.red,
  MEDIUM:   C.yellow,
  LOW:      C.cyan,
  INFO:     C.dim,
};

function colorSeverity(severity) {
  return (SEVERITY_COLOR[severity] || "") + severity + C.reset;
}

/**
 * Prints findings to stdout and optionally writes a JSON report.
 *
 * @param {Array}  findings          - Enriched findings (from severities.enrichFindings)
 * @param {Object} [options]
 * @param {string} [options.outputPath] - File path for JSON export (optional)
 */
function reportFindings(findings, { outputPath } = {}) {
  if (findings.length === 0) {
    console.log(`\n${C.green}✔  No findings at or above the selected severity threshold.${C.reset}\n`);
    return;
  }

  console.log(`\n${C.bold}=== Cloud Security Report ===${C.reset}\n`);

  for (const f of findings) {
    console.log(`[${colorSeverity(f.severity)}] ${C.bold}${f.ruleId}${C.reset}  ${C.dim}${f.resource}${C.reset}`);
    console.log(`  ${C.dim}Detail  :${C.reset} ${f.detail}`);
    console.log(`  ${C.dim}Impact  :${C.reset} ${f.impact}`);
    console.log(`  ${C.dim}Fix     :${C.reset} ${f.remediation}`);
    console.log();
  }

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const summaryLine = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    .map((s) => `${colorSeverity(s)}: ${counts[s] || 0}`)
    .join("  ");

  console.log("─".repeat(60));
  console.log(`${C.bold}SUMMARY${C.reset}  ${summaryLine}  ${C.dim}(Total: ${findings.length})${C.reset}\n`);

  if (outputPath) {
    const report = {
      generatedAt:   new Date().toISOString(),
      totalFindings: findings.length,
      summary:       counts,
      findings,
    };
    try {
      fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
      fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf8");
      console.log(`${C.green}JSON report written to:${C.reset} ${outputPath}\n`);
    } catch (err) {
      console.error(`[WARN] Could not write JSON report: ${err.message}`);
    }
  }
}

module.exports = { reportFindings };
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npx jest tests/utils/reporter.test.js --no-coverage
```

Expected: PASS — all 5 tests green.

- [ ] **Step 5: Commit**

```bash
git add src/utils/reporter.js tests/utils/reporter.test.js
git commit -m "feat: add reporter with ANSI output, summary block, and JSON export"
```

---

## Task 6: IAM Scanner

**Files:**
- Create: `src/scanners/iamScanner.js`

Note: Integration-tested via a real AWS account. Unit test for the arg parser is in Task 8.

- [ ] **Step 1: Write `src/scanners/iamScanner.js`**

```js
// src/scanners/iamScanner.js
// Paginates through all IAM roles and fetches their trust policy,
// attached managed policies, and inline policy documents.

const {
  ListRolesCommand,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
} = require("@aws-sdk/client-iam");
const { iam } = require("../config/aws");

/**
 * Paginates ListRoles using the Marker field until IsTruncated is false.
 * AWS SDK v3 does not auto-paginate this command.
 */
async function getAllRoles() {
  const roles = [];
  let marker;
  do {
    const resp = await iam.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
    roles.push(...(resp.Roles || []));
    marker = resp.IsTruncated ? resp.Marker : undefined;
  } while (marker);
  return roles;
}

async function scanIAM() {
  const rawRoles = await getAllRoles();
  const results  = [];

  for (const role of rawRoles) {
    const roleName = role.RoleName;

    // CRITICAL: AssumeRolePolicyDocument from ListRoles is URL-encoded JSON.
    // Failing to decode it causes JSON.parse to throw on every role.
    let trustPolicy = null;
    try {
      trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
    } catch (_) {
      // Malformed trust policy — rule engine handles null safely.
    }

    const attachedResp = await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }));
    const attachedPolicies = attachedResp.AttachedPolicies || [];

    const inlineNamesResp = await iam.send(new ListRolePoliciesCommand({ RoleName: roleName }));
    const inlinePolicies  = [];

    for (const policyName of inlineNamesResp.PolicyNames || []) {
      try {
        const polResp = await iam.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: policyName }));
        // GetRolePolicy also returns the document URL-encoded.
        const document = JSON.parse(decodeURIComponent(polResp.PolicyDocument));
        inlinePolicies.push({ name: policyName, document });
      } catch (_) {
        // Skip unreadable policies gracefully.
      }
    }

    results.push({ name: roleName, trustPolicy, attachedPolicies, inlinePolicies });
  }

  return results;
}

module.exports = { scanIAM };
```

- [ ] **Step 2: Verify the module loads**

```bash
node -e "require('./src/scanners/iamScanner'); console.log('iamScanner loaded OK');"
```

Expected: `iamScanner loaded OK`

- [ ] **Step 3: Commit**

```bash
git add src/scanners/iamScanner.js
git commit -m "feat: add IAM scanner with pagination and URL-decoded policy documents"
```

---

## Task 7: S3 and EC2 Scanners

**Files:**
- Create: `src/scanners/s3Scanner.js`
- Create: `src/scanners/ec2Scanner.js`

- [ ] **Step 1: Write `src/scanners/s3Scanner.js`**

```js
// src/scanners/s3Scanner.js
// Fetches ACL, bucket policy, encryption config, and Block Public Access
// for every S3 bucket in the account. All four calls are made in parallel
// per bucket. A null result means the config is absent (treated as insecure by rules).

const {
  ListBucketsCommand,
  GetBucketAclCommand,
  GetBucketPolicyCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
} = require("@aws-sdk/client-s3");
const { s3 } = require("../config/aws");

/**
 * Attempts a single S3 command. Returns null on any error.
 *
 * Expected AWS error codes that are NOT bugs:
 *   - NoSuchPublicAccessBlockConfiguration (404) — BPA not set
 *   - ServerSideEncryptionConfigurationNotFoundError (404) — no encryption rule
 *   - NoSuchBucketPolicy (404) — no bucket policy exists
 *
 * Returning null lets the analysis layer distinguish "not configured" (insecure)
 * from "explicitly configured" — which is exactly what several rules check.
 */
async function tryFetch(command) {
  try {
    return await s3.send(command);
  } catch (_) {
    return null;
  }
}

async function scanS3() {
  const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));
  const results = [];

  for (const bucket of Buckets) {
    const name = bucket.Name;

    // All four calls run in parallel for performance (ListBuckets doesn't paginate).
    const [acl, policyResp, encryption, publicAccessBlock] = await Promise.all([
      tryFetch(new GetBucketAclCommand({ Bucket: name })),
      tryFetch(new GetBucketPolicyCommand({ Bucket: name })),
      tryFetch(new GetBucketEncryptionCommand({ Bucket: name })),
      tryFetch(new GetPublicAccessBlockCommand({ Bucket: name })),
    ]);

    results.push({
      name,
      acl,
      policyText:        policyResp?.Policy ?? null,
      encryption,
      publicAccessBlock,
    });
  }

  return results;
}

module.exports = { scanS3 };
```

- [ ] **Step 2: Write `src/scanners/ec2Scanner.js`**

```js
// src/scanners/ec2Scanner.js
// Returns all security groups in the configured region, fully paginated.
// Each object includes IpPermissions[].Ipv6Ranges[] for IPv6 CIDR detection.

const { DescribeSecurityGroupsCommand } = require("@aws-sdk/client-ec2");
const { ec2 } = require("../config/aws");

async function scanEC2() {
  const groups = [];
  let nextToken;

  do {
    const resp = await ec2.send(
      new DescribeSecurityGroupsCommand({ NextToken: nextToken, MaxResults: 100 })
    );
    groups.push(...(resp.SecurityGroups || []));
    nextToken = resp.NextToken;
  } while (nextToken);

  return groups;
}

module.exports = { scanEC2 };
```

- [ ] **Step 3: Verify both modules load**

```bash
node -e "require('./src/scanners/s3Scanner'); require('./src/scanners/ec2Scanner'); console.log('scanners loaded OK');"
```

Expected: `scanners loaded OK`

- [ ] **Step 4: Commit**

```bash
git add src/scanners/s3Scanner.js src/scanners/ec2Scanner.js
git commit -m "feat: add S3 and EC2 scanners with pagination and parallel per-bucket fetches"
```

---

## Task 8: CLI entry point and arg parser tests

**Files:**
- Create: `src/cli/index.js`
- Create: `tests/cli/parseArgs.test.js`

- [ ] **Step 1: Write the failing tests for parseArgs**

```js
// tests/cli/parseArgs.test.js
// parseArgs is an exported helper so it can be unit tested independently.
const { parseArgs } = require("../../src/cli/index");

describe("parseArgs", () => {
  it("parses --key=value format", () => {
    const args = parseArgs(["node", "index.js", "--services=iam,s3"]);
    expect(args.services).toBe("iam,s3");
  });

  it("parses --key value format", () => {
    const args = parseArgs(["node", "index.js", "--min-severity", "HIGH"]);
    expect(args["min-severity"]).toBe("HIGH");
  });

  it("returns an empty object when no flags are given", () => {
    const args = parseArgs(["node", "index.js"]);
    expect(args).toEqual({});
  });

  it("handles multiple flags in one call", () => {
    const args = parseArgs(["node", "index.js", "--services=ec2", "--format=json", "--output=./out.json"]);
    expect(args.services).toBe("ec2");
    expect(args.format).toBe("json");
    expect(args.output).toBe("./out.json");
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npx jest tests/cli/parseArgs.test.js --no-coverage
```

Expected: FAIL — `Cannot find module '../../src/cli/index'`

- [ ] **Step 3: Write `src/cli/index.js`**

```js
// src/cli/index.js
// Orchestrates the full scan pipeline. Parses CLI flags, runs selected
// scanners, enriches and filters findings, outputs results, and sets
// exit code 1 when CRITICAL or HIGH findings are present (for CI).

const { scanS3 }  = require("../scanners/s3Scanner");
const { scanIAM } = require("../scanners/iamScanner");
const { scanEC2 } = require("../scanners/ec2Scanner");

const { analyzeIAM, analyzeS3, analyzeSecurityGroups } = require("../analysis/rules");
const { enrichFindings, meetsMinSeverity }             = require("../analysis/severities");
const { reportFindings }                               = require("../utils/reporter");
const { REGION }                                       = require("../config/aws");

/**
 * Minimal flag parser — supports --key=value and --key value formats.
 * Exported so it can be unit tested independently.
 *
 * @param {string[]} argv - typically process.argv
 * @returns {Object} key→value map (keys without the leading --)
 */
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].includes("=")) {
      const [key, val] = argv[i].split("=");
      args[key.replace(/^--/, "")] = val;
    } else if (argv[i].startsWith("--")) {
      const key = argv[i].replace(/^--/, "");
      const next = argv[i + 1];
      args[key] = (next && !next.startsWith("--")) ? next : true;
      if (next && !next.startsWith("--")) i++;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);

  const services    = (args.services          || "iam,s3,ec2").split(",").map((s) => s.trim());
  const minSeverity = (args["min-severity"]   || "INFO").toUpperCase();
  const format      = (args.format            || "table").toLowerCase();
  const outputPath  =  args.output            || null;

  console.log(`\nCloud Security Scanner — Region: ${REGION}`);
  console.log(`Services: ${services.join(", ")} | Min severity: ${minSeverity}\n`);

  try {
    const rawFindings = [];

    if (services.includes("iam")) {
      console.log("Scanning IAM...");
      rawFindings.push(...analyzeIAM(await scanIAM()));
    }

    if (services.includes("s3")) {
      console.log("Scanning S3...");
      rawFindings.push(...analyzeS3(await scanS3()));
    }

    if (services.includes("ec2")) {
      console.log("Scanning EC2 security groups...");
      rawFindings.push(...analyzeSecurityGroups(await scanEC2()));
    }

    const enriched = enrichFindings(rawFindings);
    const filtered = enriched.filter((f) => meetsMinSeverity(f, minSeverity));

    if (format === "json") {
      console.log(JSON.stringify({ generatedAt: new Date().toISOString(), findings: filtered }, null, 2));
    } else {
      reportFindings(filtered, { outputPath });
    }

    const hasCriticalOrHigh = filtered.some((f) => ["CRITICAL", "HIGH"].includes(f.severity));
    if (hasCriticalOrHigh) process.exitCode = 1;

  } catch (err) {
    console.error(`\n[ERROR] Scan failed: ${err.message || err}`);

    if (err.name === "CredentialsProviderError") {
      console.error(
        "\nHint: No AWS credentials found. Set AWS_PROFILE, AWS_ACCESS_KEY_ID," +
        "\n      or attach an IAM role to the compute environment."
      );
    }

    if (err.name === "AccessDeniedException" || err.$metadata?.httpStatusCode === 403) {
      console.error(
        "\nHint: Access denied. Ensure the scanning identity has the minimum" +
        "\n      IAM policy described in the project README."
      );
    }

    process.exitCode = 1;
  }
}

// Only run main when this file is the entry point, not when require()'d by tests.
if (require.main === module) {
  main();
}

module.exports = { parseArgs };
```

- [ ] **Step 4: Run parseArgs tests to confirm they pass**

```bash
npx jest tests/cli/parseArgs.test.js --no-coverage
```

Expected: PASS — all 4 tests green.

- [ ] **Step 5: Commit**

```bash
git add src/cli/index.js tests/cli/parseArgs.test.js
git commit -m "feat: add CLI entry point with arg parsing, pipeline orchestration, and CI exit codes"
```

---

## Task 9: Full test suite and README

**Files:**
- Create: `README.md`
- Modify: `jest.config.js` (new)

- [ ] **Step 1: Add jest config to package.json for test discovery**

Add a `"jest"` key to `package.json`:

```json
"jest": {
  "testMatch": ["**/tests/**/*.test.js"],
  "collectCoverageFrom": ["src/**/*.js"]
}
```

- [ ] **Step 2: Run full test suite**

```bash
npx jest --coverage
```

Expected: All tests pass. Coverage report printed. No failures.

- [ ] **Step 3: Create README.md**

```markdown
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
```

- [ ] **Step 4: Commit**

```bash
git add README.md package.json
git commit -m "docs: add README and jest config"
```

---

## Task 10: Final integration smoke test

- [ ] **Step 1: Run the full test suite one final time**

```bash
npx jest --coverage
```

Expected: All tests pass. No failures.

- [ ] **Step 2: Verify the CLI loads without error (no AWS creds needed for this)**

```bash
node -e "
const { parseArgs } = require('./src/cli/index');
console.log(parseArgs(['node','index.js','--services=iam','--min-severity=HIGH']));
"
```

Expected output:
```
{ services: 'iam', 'min-severity': 'HIGH' }
```

- [ ] **Step 3: Dry-run with missing credentials to confirm error handling**

```bash
AWS_ACCESS_KEY_ID=fake AWS_SECRET_ACCESS_KEY=fake node src/cli/index.js --services=iam 2>&1 | head -10
```

Expected: Graceful error message, no unhandled promise rejection, exit code 1.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final smoke test pass — cloud-security scanner v1.0"
```
