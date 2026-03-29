// src/cli/index.js
// Orchestrates the full scan pipeline. Parses CLI flags, runs selected
// scanners, enriches and filters findings, outputs results, and sets
// exit code 1 when CRITICAL or HIGH findings are present (for CI).

const { scanS3 }  = require("../scanners/s3Scanner");
const { scanIAM } = require("../scanners/iamScanner");
const { scanEC2 } = require("../scanners/ec2Scanner");

const { analyzeIAM, analyzeS3, analyzeSecurityGroups } = require("../analysis/rules");
const { enrichFindings, meetsMinSeverity, SEVERITY_ORDER } = require("../analysis/severities");
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

  const KNOWN_SERVICES = new Set(["iam", "s3", "ec2"]);
  const services = (args.services || "iam,s3,ec2")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => {
      if (!KNOWN_SERVICES.has(s)) {
        console.warn(`[WARN] Unknown service "${s}" — skipping. Known services: iam, s3, ec2`);
        return false;
      }
      return true;
    });

  const minSeverity = (args["min-severity"]   || "INFO").toUpperCase();
  if (!SEVERITY_ORDER.includes(minSeverity)) {
    console.error(`[ERROR] Invalid --min-severity "${minSeverity}". Valid values: ${SEVERITY_ORDER.join(", ")}`);
    process.exitCode = 1;
    return;
  }

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
      // JSON format prints to stdout; use shell redirection to write to a file (e.g. > report.json).
      // The --output flag is only honoured in table format.
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
