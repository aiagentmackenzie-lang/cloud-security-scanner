// src/utils/reporter.js
// Terminal output (ANSI colours, summary block) + optional JSON file export.
// ANSI codes are stripped automatically when stdout is not a TTY (CI, pipes).

const fs   = require("fs");
const path = require("path");

const isTTY = process.stdout.isTTY;
const C = {
  reset:   isTTY ? "\x1b[0m"  : "",
  bold:    isTTY ? "\x1b[1m"  : "",
  dim:     isTTY ? "\x1b[2m"  : "",
  red:     isTTY ? "\x1b[31m" : "",
  yellow:  isTTY ? "\x1b[33m" : "",
  cyan:    isTTY ? "\x1b[36m" : "",
  green:   isTTY ? "\x1b[32m" : "",
};

const SEVERITY_COLOR = {
  CRITICAL: C.red  + C.bold,
  HIGH:     C.red,
  MEDIUM:   C.yellow,
  LOW:      C.cyan,
  INFO:     C.dim,
};

function colorSeverity(severity) {
  return (SEVERITY_COLOR[severity] || "") + severity + C.reset;
}

/**
 * Prints findings to stdout and optionally writes a JSON report.
 *
 * @param {Array}  findings          - Enriched findings (from severities.enrichFindings)
 * @param {Object} [options]
 * @param {string} [options.outputPath] - File path for JSON export (optional)
 */
function reportFindings(findings, { outputPath } = {}) {
  if (findings.length === 0) {
    console.log(`\n${C.green}✔  No findings at or above the selected severity threshold.${C.reset}\n`);
    return;
  }

  console.log(`\n${C.bold}=== Cloud Security Report ===${C.reset}\n`);

  for (const f of findings) {
    console.log(`[${colorSeverity(f.severity)}] ${C.bold}${f.ruleId}${C.reset}  ${C.dim}${f.resource}${C.reset}`);
    console.log(`  ${C.dim}Detail  :${C.reset} ${f.detail}`);
    console.log(`  ${C.dim}Impact  :${C.reset} ${f.impact}`);
    console.log(`  ${C.dim}Fix     :${C.reset} ${f.remediation}`);
    console.log();
  }

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const summaryLine = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    .map((s) => `${colorSeverity(s)}: ${counts[s] || 0}`)
    .join("  ");

  console.log("─".repeat(60));
  console.log(`${C.bold}SUMMARY${C.reset}  ${summaryLine}  ${C.dim}(Total: ${findings.length})${C.reset}\n`);

  if (outputPath) {
    const report = {
      generatedAt:   new Date().toISOString(),
      totalFindings: findings.length,
      summary:       counts,
      findings,
    };
    try {
      fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
      fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf8");
      console.log(`${C.green}JSON report written to:${C.reset} ${outputPath}\n`);
    } catch (err) {
      console.error(`[WARN] Could not write JSON report: ${err.message}`);
    }
  }
}

module.exports = { reportFindings };
