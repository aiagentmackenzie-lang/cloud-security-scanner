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

  it("handles --key=val=ue with multiple equals signs (value includes remaining =)", () => {
    const args = parseArgs(["node", "index.js", "--output=./reports/2026=04"]);
    expect(args.output).toBe("./reports/2026=04");
  });

  it("stores empty string for --key= with no value after equals", () => {
    const args = parseArgs(["node", "index.js", "--output="]);
    expect(args.output).toBe("");
  });

  // BUG-4: --services= should NOT fall back to default.
  // An explicit empty string means the user wants no services,
  // which should be caught by the main() validation.
  it("preserves empty string for --services= (does not fall back to default)", () => {
    const args = parseArgs(["node", "index.js", "--services="]);
    // The empty string must survive so main() can detect it as invalid.
    expect(args.services).toBe("");
  });
});
