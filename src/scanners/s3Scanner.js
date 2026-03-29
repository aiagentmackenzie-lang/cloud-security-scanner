// src/scanners/s3Scanner.js
// Fetches ACL, bucket policy, encryption config, and Block Public Access
// for every S3 bucket in the account. All four calls are made in parallel
// per bucket, and all buckets are scanned concurrently.
// A null result means the config is absent (treated as insecure by rules).

const {
  ListBucketsCommand,
  GetBucketAclCommand,
  GetBucketPolicyCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
} = require("@aws-sdk/client-s3");
const { s3 } = require("../config/aws");

// These are expected "not configured" responses (HTTP 404-equivalent).
// Any other error code likely means a permission problem or unexpected failure.
const EXPECTED_MISSING_CODES = new Set([
  "NoSuchPublicAccessBlockConfiguration",
  "ServerSideEncryptionConfigurationNotFoundError",
  "NoSuchBucketPolicy",
]);

/**
 * Attempts a single S3 command. Returns null when the resource is absent
 * (expected 404-style errors). Emits a warning for any other error so that
 * AccessDenied and similar permission issues are surfaced rather than silently
 * producing false-positive findings.
 */
async function tryFetch(command, bucketName) {
  try {
    return await s3.send(command);
  } catch (err) {
    if (!EXPECTED_MISSING_CODES.has(err.name) && !EXPECTED_MISSING_CODES.has(err.Code)) {
      console.warn(`[WARN] S3 fetch failed for bucket "${bucketName}": ${err.name || err.Code} — ${err.message}`);
    }
    return null;
  }
}

async function scanS3() {
  // ListBuckets doesn't paginate — one call returns all buckets.
  const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));

  const results = await Promise.all(
    Buckets.map(async (bucket) => {
      const name = bucket.Name;

      const [acl, policyResp, encryption, publicAccessBlock] = await Promise.all([
        tryFetch(new GetBucketAclCommand({ Bucket: name }), name),
        tryFetch(new GetBucketPolicyCommand({ Bucket: name }), name),
        tryFetch(new GetBucketEncryptionCommand({ Bucket: name }), name),
        tryFetch(new GetPublicAccessBlockCommand({ Bucket: name }), name),
      ]);

      return {
        name,
        acl,
        policyText:        policyResp?.Policy ?? null,
        encryption,
        publicAccessBlock,
      };
    })
  );

  return results;
}

module.exports = { scanS3 };
