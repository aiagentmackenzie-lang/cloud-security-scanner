// src/cli/index.js
// Orchestrates the full scan pipeline. Parses CLI flags, runs selected
// scanners, enriches and filters findings, outputs results, and sets
// exit code 1 when CRITICAL or HIGH findings are present (for CI).
//
// BUG-1 fix: Each scanner runs in its own try/catch so a failure in one
// service does not prevent the others from running. Partial results are
// still reported. Exit code 1 is set if any scan fails or if any
// CRITICAL/HIGH finding is present.
//
// BUG-3 fix: JSON output includes totalFindings and summary for schema
// consistency with the reporter's JSON file format.
//
// BUG-4 fix: --services= (empty) uses nullish coalescing so the empty
// string is not silently replaced by the default.
//
// BUG-5 fix: --format is validated against table|json; invalid values
// produce a clear error and exit 1.

const { scanS3 }  = require("../scanners/s3Scanner");
const { scanIAM } = require("../scanners/iamScanner");
const { scanEC2 } = require("../scanners/ec2Scanner");

const { analyzeIAM, analyzeS3, analyzeSecurityGroups } = require("../analysis/rules");
const { enrichFindings, meetsMinSeverity, SEVERITY_ORDER } = require("../analysis/severities");
const { reportFindings }                               = require("../utils/reporter");
const { REGION }                                       = require("../config/aws");

const VALID_FORMATS = new Set(["table", "json"]);

/**
 * Print a standardised error hint for common AWS SDK errors.
 */
function printErrorHint(err) {
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
}

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
      const eqIdx = argv[i].indexOf("=");
      const key = argv[i].slice(0, eqIdx).replace(/^--/, "");
      const val = argv[i].slice(eqIdx + 1);
      args[key] = val;
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

  // BUG-4: Use nullish coalescing so an explicit empty string (--services=)
  // is not silently replaced by the default. An empty string will cause the
  // filter below to produce zero services, which then triggers the error exit.
  const KNOWN_SERVICES = new Set(["iam", "s3", "ec2"]);
  const services = (args.services ?? "iam,s3,ec2")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => {
      if (!KNOWN_SERVICES.has(s)) {
        console.warn(`[WARN] Unknown service "${s}" — skipping. Known services: iam, s3, ec2`);
        return false;
      }
      return true;
    });

  if (services.length === 0) {
    console.error("[ERROR] No valid services to scan. Use: iam, s3, ec2");
    process.exitCode = 1;
    return;
  }

  const minSeverity = (args["min-severity"] || "INFO").toUpperCase();
  if (!SEVERITY_ORDER.includes(minSeverity)) {
    console.error(`[ERROR] Invalid --min-severity "${minSeverity}". Valid values: ${SEVERITY_ORDER.join(", ")}`);
    process.exitCode = 1;
    return;
  }

  // BUG-5: Validate --format against allowed values to prevent silent
  // fallback to table mode on typos like --format=josn.
  const format = (args.format || "table").toLowerCase();
  if (!VALID_FORMATS.has(format)) {
    console.error(`[ERROR] Invalid --format "${format}". Valid values: ${[...VALID_FORMATS].join(", ")}`);
    process.exitCode = 1;
    return;
  }

  const outputPath = args.output || null;

  console.log(`\nCloud Security Scanner — Region: ${REGION}`);
  console.log(`Services: ${services.join(", ")} | Min severity: ${minSeverity}\n`);

  // BUG-1: Each scanner runs in its own try/catch so a failure in one
  // service does not prevent the others from running.
  const rawFindings = [];
  const failedScans = [];

  if (services.includes("iam")) {
    console.log("Scanning IAM...");
    try {
      rawFindings.push(...analyzeIAM(await scanIAM()));
    } catch (err) {
      failedScans.push("iam");
      console.error(`\n[ERROR] IAM scan failed: ${err.message || err}`);
      printErrorHint(err);
    }
  }

  if (services.includes("s3")) {
    console.log("Scanning S3...");
    try {
      rawFindings.push(...analyzeS3(await scanS3()));
    } catch (err) {
      failedScans.push("s3");
      console.error(`\n[ERROR] S3 scan failed: ${err.message || err}`);
      printErrorHint(err);
    }
  }

  if (services.includes("ec2")) {
    console.log("Scanning EC2 security groups...");
    try {
      rawFindings.push(...analyzeSecurityGroups(await scanEC2()));
    } catch (err) {
      failedScans.push("ec2");
      console.error(`\n[ERROR] EC2 scan failed: ${err.message || err}`);
      printErrorHint(err);
    }
  }

  if (failedScans.length === services.length) {
    console.error("\n[ERROR] All requested scans failed. No findings were collected.");
    process.exitCode = 1;
    return;
  }

  if (failedScans.length > 0) {
    console.warn(`\n[WARN] Scans failed for: ${failedScans.join(", ")}. Results may be incomplete.`);
  }

  const enriched = enrichFindings(rawFindings);
  const filtered = enriched.filter((f) => meetsMinSeverity(f, minSeverity));

  // BUG-3: JSON output schema now includes totalFindings and summary to
  // match the reporter's JSON file format for consistency.
  if (format === "json") {
    const counts = filtered.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});

    const payload = JSON.stringify({
      generatedAt:   new Date().toISOString(),
      totalFindings: filtered.length,
      summary:       counts,
      findings:      filtered,
    }, null, 2);

    if (outputPath) {
      const fs = require("fs");
      const path = require("path");
      const resolvedPath = path.resolve(outputPath);
      fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
      fs.writeFileSync(resolvedPath, payload, "utf8");
      console.log(`JSON report written to: ${outputPath}`);
    } else {
      console.log(payload);
    }
  } else {
    reportFindings(filtered, { outputPath });
  }

  const hasCriticalOrHigh = filtered.some((f) => ["CRITICAL", "HIGH"].includes(f.severity));
  if (hasCriticalOrHigh || failedScans.length > 0) process.exitCode = 1;
}

// Only run main when this file is the entry point, not when require()'d by tests.
if (require.main === module) {
  main();
}

module.exports = { parseArgs };