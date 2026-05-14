// tests/cli/exitCodes.test.js
// Integration-level tests that spawn the CLI process to verify exit codes
// and argument validation errors.

const { spawnSync } = require("child_process");
const path = require("path");

const CLI = path.resolve(__dirname, "../../src/cli/index.js");

function runCLI(args) {
  return spawnSync("node", [CLI, ...args], { encoding: "utf8" });
}

describe("CLI exit codes", () => {
  it("exits 1 when --services contains only unknown services", () => {
    const result = runCLI(["--services=rds"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/no valid services/i);
  });

  // BUG-4: --services= (empty string) should not fall back to default services.
  // It should produce zero valid services and exit 1.
  it("exits 1 when --services= is empty (no fallback to default)", () => {
    const result = runCLI(["--services="]);
    expect(result.status).toBe(1);
    // The empty string is filtered out by the KNOWN_SERVICES check,
    // leaving zero services, which triggers the error.
    expect(result.stderr).toMatch(/no valid services/i);
  });

  // BUG-5: Invalid --format values should be rejected.
  it("exits 1 when --format is invalid", () => {
    const result = runCLI(["--format=xml", "--services=iam"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/invalid --format/i);
  });
});