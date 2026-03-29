// src/scanners/iamScanner.js
// Paginates through all IAM roles and fetches their trust policy,
// attached managed policies, and inline policy documents.

const {
  ListRolesCommand,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
} = require("@aws-sdk/client-iam");
const { iam } = require("../config/aws");

/**
 * Paginates ListRoles using the Marker field until IsTruncated is false.
 * AWS SDK v3 does not auto-paginate this command.
 */
async function getAllRoles() {
  const roles = [];
  let marker;
  do {
    const resp = await iam.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
    roles.push(...(resp.Roles || []));
    marker = resp.IsTruncated ? resp.Marker : undefined;
  } while (marker);
  return roles;
}

/**
 * Paginates ListAttachedRolePolicies for a given role.
 */
async function getAttachedPolicies(roleName) {
  const policies = [];
  let marker;
  do {
    const resp = await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName, Marker: marker, MaxItems: 100 }));
    policies.push(...(resp.AttachedPolicies || []));
    marker = resp.IsTruncated ? resp.Marker : undefined;
  } while (marker);
  return policies;
}

/**
 * Paginates ListRolePolicies (inline policy names) for a given role.
 */
async function getInlinePolicyNames(roleName) {
  const names = [];
  let marker;
  do {
    const resp = await iam.send(new ListRolePoliciesCommand({ RoleName: roleName, Marker: marker, MaxItems: 100 }));
    names.push(...(resp.PolicyNames || []));
    marker = resp.IsTruncated ? resp.Marker : undefined;
  } while (marker);
  return names;
}

async function scanIAM() {
  const rawRoles = await getAllRoles();
  const results  = [];

  for (const role of rawRoles) {
    const roleName = role.RoleName;

    // CRITICAL: AssumeRolePolicyDocument from ListRoles is URL-encoded JSON.
    // Failing to decode it causes JSON.parse to throw on every role.
    let trustPolicy = null;
    try {
      trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
    } catch (_) {
      // Malformed trust policy — rule engine handles null safely.
    }

    let attachedPolicies = [];
    try {
      attachedPolicies = await getAttachedPolicies(roleName);
    } catch (err) {
      console.warn(`[WARN] Could not list attached policies for role "${roleName}": ${err.message}`);
    }

    let inlinePolicyNames = [];
    try {
      inlinePolicyNames = await getInlinePolicyNames(roleName);
    } catch (err) {
      console.warn(`[WARN] Could not list inline policy names for role "${roleName}": ${err.message}`);
    }

    const inlinePolicies = [];

    for (const policyName of inlinePolicyNames) {
      try {
        const polResp = await iam.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: policyName }));
        // GetRolePolicy also returns the document URL-encoded.
        const document = JSON.parse(decodeURIComponent(polResp.PolicyDocument));
        inlinePolicies.push({ name: policyName, document });
      } catch (err) {
        console.warn(`[WARN] Could not fetch inline policy "${policyName}" for role "${roleName}": ${err.message}`);
      }
    }

    results.push({ name: roleName, trustPolicy, attachedPolicies, inlinePolicies });
  }

  return results;
}

module.exports = { scanIAM };
