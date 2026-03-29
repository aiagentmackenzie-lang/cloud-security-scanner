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

    let bucketPolicy = null;
    if (bucket.policyText) {
      try { bucketPolicy = JSON.parse(bucket.policyText); } catch (_) { /* malformed policy */ }
    }

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
    if (bucketPolicy?.Statement) {
      for (const stmt of bucketPolicy.Statement) {
        if (
          stmt.Effect === "Allow" &&
          (stmt.Principal === "*" || stmt.Principal?.AWS === "*")
        ) {
          findings.push({
            ruleId:   "S3-002",
            resource,
            detail:   `Bucket policy allows Principal: * on an Allow statement`,
          });
          break;
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
    const hasSecureTransportDeny = bucketPolicy?.Statement?.some((stmt) => {
      if (stmt.Effect !== "Deny") return false;
      const condition = stmt.Condition;
      return (
        condition?.Bool?.["aws:SecureTransport"] === "false" ||
        condition?.Bool?.["aws:SecureTransport"] === false
      );
    }) ?? false;

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
  const spansAdminPort = fromPort !== null && toPort !== null &&
    [...ADMIN_PORTS].some((p) => p >= fromPort && p <= toPort);

  if (spansAdminPort) {
    const exposedAdminPorts = [...ADMIN_PORTS].filter((p) => p >= fromPort && p <= toPort);
    const portDesc = exposedAdminPorts.length === 1
      ? `Admin port ${exposedAdminPorts[0]}`
      : `Admin ports ${exposedAdminPorts.join(",")}`;

    findings.push({
      ruleId:   "NET-001",
      resource: `ec2:security-group/${sgId}`,
      detail:   `${portDesc} open to ${cidr} on ${label}`,
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
