// src/scanners/s3Scanner.js
// Fetches ACL, bucket policy, encryption config, and Block Public Access
// for every S3 bucket in the account. All four calls are made in parallel
// per bucket. A null result means the config is absent (treated as insecure by rules).

const {
  ListBucketsCommand,
  GetBucketAclCommand,
  GetBucketPolicyCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
} = require("@aws-sdk/client-s3");
const { s3 } = require("../config/aws");

/**
 * Attempts a single S3 command. Returns null on any error.
 *
 * Expected AWS error codes that are NOT bugs:
 *   - NoSuchPublicAccessBlockConfiguration (404) — BPA not set
 *   - ServerSideEncryptionConfigurationNotFoundError (404) — no encryption rule
 *   - NoSuchBucketPolicy (404) — no bucket policy exists
 *
 * Returning null lets the analysis layer distinguish "not configured" (insecure)
 * from "explicitly configured" — which is exactly what several rules check.
 */
async function tryFetch(command) {
  try {
    return await s3.send(command);
  } catch (_) {
    return null;
  }
}

async function scanS3() {
  const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));
  const results = [];

  for (const bucket of Buckets) {
    const name = bucket.Name;

    // All four calls run in parallel for performance (ListBuckets doesn't paginate).
    const [acl, policyResp, encryption, publicAccessBlock] = await Promise.all([
      tryFetch(new GetBucketAclCommand({ Bucket: name })),
      tryFetch(new GetBucketPolicyCommand({ Bucket: name })),
      tryFetch(new GetBucketEncryptionCommand({ Bucket: name })),
      tryFetch(new GetPublicAccessBlockCommand({ Bucket: name })),
    ]);

    results.push({
      name,
      acl,
      policyText:        policyResp?.Policy ?? null,
      encryption,
      publicAccessBlock,
    });
  }

  return results;
}

module.exports = { scanS3 };
