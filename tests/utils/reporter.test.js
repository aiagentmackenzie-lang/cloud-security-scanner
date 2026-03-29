// tests/utils/reporter.test.js
const fs   = require("fs");
const path = require("path");
const os   = require("os");

// Capture stdout without mocking the entire console
let output = "";
let errorOutput = "";
const originalLog = console.log;
const originalError = console.error;
beforeEach(() => {
  output = "";
  errorOutput = "";
  console.log = (...args) => { output += args.join(" ") + "\n"; };
  console.error = (...args) => { errorOutput += args.join(" ") + "\n"; };
});
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

  it("logs a warning when the output file cannot be written", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cloud-sec-test-"));
    // Create a FILE at the path that mkdirSync will try to use as a directory
    const blockingFile = path.join(tmpDir, "blocker");
    fs.writeFileSync(blockingFile, "I am a file, not a dir");
    const outFile = path.join(blockingFile, "report.json"); // parent is a file — will throw
    expect(() => reportFindings(makeFindings(), { outputPath: outFile })).not.toThrow();
    expect(errorOutput).toMatch(/\[WARN\]/);
    fs.rmSync(tmpDir, { recursive: true });
  });
});
