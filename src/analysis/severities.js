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
