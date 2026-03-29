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
