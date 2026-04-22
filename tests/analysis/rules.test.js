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

  it("flags IAM-001 when Statement is a single object (not array) with wildcard", () => {
    const roles = [{
      name: "single-stmt-role",
      trustPolicy: null,
      attachedPolicies: [],
      inlinePolicies: [{
        name: "bad-inline",
        document: {
          Statement: { Effect: "Allow", Action: "*", Resource: "arn:aws:s3:::bucket/*" },
        },
      }],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-001")).toBe(true);
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

  it("flags IAM-003 for a trust policy with Principal: { AWS: '*' }", () => {
    const roles = [{
      name: "public-role-2",
      trustPolicy: {
        Statement: [{
          Effect: "Allow",
          Principal: { AWS: "*" },
          Action: "sts:AssumeRole",
        }],
      },
      attachedPolicies: [],
      inlinePolicies: [],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-003")).toBe(true);
  });

  it("flags IAM-003 for Principal as array containing '*' (S3-002 backport)", () => {
    const roles = [{
      name: "public-role-array",
      trustPolicy: {
        Statement: [{
          Effect: "Allow",
          Principal: ["*"],
          Action: "sts:AssumeRole",
        }],
      },
      attachedPolicies: [],
      inlinePolicies: [],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-003")).toBe(true);
  });

  it("flags IAM-003 for Principal.AWS as array containing '*'", () => {
    const roles = [{
      name: "public-role-aws-array",
      trustPolicy: {
        Statement: [{
          Effect: "Allow",
          Principal: { AWS: ["arn:aws:iam::123:root", "*"] },
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

  it("flags IAM-003 when trust policy Statement is a single object (not array)", () => {
    const roles = [{
      name: "public-single-stmt",
      trustPolicy: {
        Statement: { Effect: "Allow", Principal: "*", Action: "sts:AssumeRole" },
      },
      attachedPolicies: [],
      inlinePolicies: [],
    }];
    const findings = analyzeIAM(roles);
    expect(findings.some((f) => f.ruleId === "IAM-003")).toBe(true);
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
        Statement: [
          { Effect: "Allow", Principal: { AWS: "arn:aws:iam::123456789012:root" }, Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" },
          { Effect: "Deny", Action: "s3:*", Principal: "*", Condition: { Bool: { "aws:SecureTransport": "false" } } },
        ],
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
      Statement: [
        { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" },
        { Effect: "Deny", Action: "s3:*", Principal: "*", Condition: { Bool: { "aws:SecureTransport": "false" } } },
      ],
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

  it("flags S3-002 when bucket policy Statement is a single object with Principal: *", () => {
    const bucket = makeCleanBucket();
    bucket.policyText = JSON.stringify({
      Statement: { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" },
    });
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-002")).toBe(true);
  });

  it("flags S3-005 when policy Statement is a single object without SecureTransport deny", () => {
    const bucket = makeCleanBucket();
    bucket.policyText = JSON.stringify({
      Statement: { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" },
    });
    const findings = analyzeS3([bucket]);
    // No Deny statement at all
    expect(findings.some((f) => f.ruleId === "S3-005")).toBe(true);
  });

  it("flags S3-005 when bucket policy has no SecureTransport deny", () => {
    const bucket = makeCleanBucket();
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

  it("flags S3-002 when Principal is an array containing '*'", () => {
    const bucket = makeCleanBucket();
    bucket.policyText = JSON.stringify({
      Statement: [{ Effect: "Allow", Principal: ["*"], Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" }],
    });
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-002")).toBe(true);
  });

  it("flags S3-002 when Principal.AWS is an array containing '*'", () => {
    const bucket = makeCleanBucket();
    bucket.policyText = JSON.stringify({
      Statement: [{ Effect: "Allow", Principal: { AWS: ["arn:aws:iam::123:root", "*"] }, Action: "s3:GetObject", Resource: "arn:aws:s3:::my-bucket/*" }],
    });
    const findings = analyzeS3([bucket]);
    expect(findings.some((f) => f.ruleId === "S3-002")).toBe(true);
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

  it("flags NET-001 for a port range that spans an admin port (e.g. 20-22)", () => {
    const sg = makeSG({
      IpPermissions: [{
        IpProtocol: "tcp", FromPort: 20, ToPort: 22,
        IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        Ipv6Ranges: [],
      }],
    });
    const findings = analyzeSecurityGroups([sg]);
    expect(findings.some((f) => f.ruleId === "NET-001")).toBe(true);
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
