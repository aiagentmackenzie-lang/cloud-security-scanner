// tests/cli/exitCodes.test.js
// Integration-level tests that spawn the CLI process to verify exit codes.

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
});
