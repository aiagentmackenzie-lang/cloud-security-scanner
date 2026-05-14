// src/scanners/s3Scanner.js
// Fetches ACL, bucket policy, encryption config, and Block Public Access
// for every S3 bucket in the account. All four calls are made in parallel
// per bucket, and all buckets are scanned concurrently.
//
// BUG-2 fix: Determines each bucket's region via GetBucketLocation and routes
// per-bucket API calls to the correct regional S3Client. Without this, buckets
// in regions other than the scanner's default region produce misleading
// IllegalLocationConstraintException errors, causing false positives (S3-003,
// S3-004, S3-005) and false negatives (S3-001, S3-002).
//
// BUG-10 fix: Tracks which per-bucket operations returned AccessDenied and
// surfaces them as an `accessErrors` array on each bucket object so the rule
// engine can avoid false-positive findings and emit an INFO-level S3-000
// entry instead.

const {
  S3Client,
  ListBucketsCommand,
  GetBucketAclCommand,
  GetBucketPolicyCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
  GetBucketLocationCommand,
} = require("@aws-sdk/client-s3");
const { s3, REGION } = require("../config/aws");

// Cache of S3Clients keyed by region to avoid creating one per bucket.
const regionClients = new Map();
regionClients.set(REGION, s3);

function getRegionClient(region) {
  if (regionClients.has(region)) return regionClients.get(region);
  const client = new S3Client({ region });
  regionClients.set(region, client);
  return client;
}

// AWS GetBucketLocation returns "" for us-east-1 and "EU" for eu-west-1.
function normalizeBucketRegion(locationConstraint) {
  if (!locationConstraint || locationConstraint === "") return "us-east-1";
  if (locationConstraint === "EU") return "eu-west-1";
  return locationConstraint;
}

/**
 * Determines the region a bucket resides in. Falls back to the scanner's
 * default region if the call fails, in which case per-bucket calls may
 * also fail and be caught by tryFetch.
 */
async function getBucketRegion(bucketName) {
  try {
    const resp = await s3.send(new GetBucketLocationCommand({ Bucket: bucketName }));
    return normalizeBucketRegion(resp.LocationConstraint);
  } catch (err) {
    console.warn(
      `[WARN] Could not determine region for bucket "${bucketName}": ${err.name || err.Code} — ${err.message}`
    );
    return REGION;
  }
}

// These are expected "not configured" responses (HTTP 404-equivalent).
// Any other error code likely means a permission problem or unexpected failure.
const EXPECTED_MISSING_CODES = new Set([
  "NoSuchPublicAccessBlockConfiguration",
  "ServerSideEncryptionConfigurationNotFoundError",
  "NoSuchBucketPolicy",
  "IllegalLocationConstraintException",   // Cross-region bucket call w/o regional client
]);

/**
 * Attempts a single S3 command against the given client. Returns an object:
 *   { data, accessDenied }
 * - data: the SDK response, or null if the resource is absent or access was denied.
 * - accessDenied: true when the call failed due to explicit access denial (403).
 *
 * Access-denied results are tracked by the scanner so the rule engine can
 * avoid false-positive findings on missing data.
 */
async function tryFetch(command, bucketName, client = s3) {
  try {
    const data = await client.send(command);
    return { data, accessDenied: false };
  } catch (err) {
    const errCode = err.name || err.Code;
    if (EXPECTED_MISSING_CODES.has(errCode)) {
      return { data: null, accessDenied: false };
    }
    const isAccessDenied =
      errCode === "AccessDenied" ||
      errCode === "AllAccessDisabled" ||
      err.$metadata?.httpStatusCode === 403;
    if (isAccessDenied) {
      console.warn(`[WARN] Access denied for bucket "${bucketName}" — some checks may be skipped`);
    } else {
      console.warn(`[WARN] S3 fetch failed for bucket "${bucketName}": ${errCode} — ${err.message}`);
    }
    return { data: null, accessDenied: true };
  }
}

async function scanS3() {
  // ListBuckets doesn't paginate — one call returns all buckets.
  const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));

  const results = await Promise.all(
    Buckets.map(async (bucket) => {
      const name = bucket.Name;

      // BUG-2: Use the bucket's actual region so per-bucket API calls succeed.
      const bucketRegion = await getBucketRegion(name);
      const client = getRegionClient(bucketRegion);

      const [aclResult, policyResult, encryptionResult, bpaResult] = await Promise.all([
        tryFetch(new GetBucketAclCommand({ Bucket: name }), name, client),
        tryFetch(new GetBucketPolicyCommand({ Bucket: name }), name, client),
        tryFetch(new GetBucketEncryptionCommand({ Bucket: name }), name, client),
        tryFetch(new GetPublicAccessBlockCommand({ Bucket: name }), name, client),
      ]);

      // Track which operations returned AccessDenied so the rule engine can
      // suppress false-positive findings and emit an S3-000 INFO entry instead.
      const accessErrors = [];
      if (aclResult.accessDenied)          accessErrors.push("acl");
      if (policyResult.accessDenied)       accessErrors.push("policy");
      if (encryptionResult.accessDenied)  accessErrors.push("encryption");
      if (bpaResult.accessDenied)          accessErrors.push("publicAccessBlock");

      return {
        name,
        acl:               aclResult.data,
        policyText:        policyResult.data?.Policy ?? null,
        encryption:        encryptionResult.data,
        publicAccessBlock: bpaResult.data,
        accessErrors,
      };
    })
  );

  return results;
}

module.exports = { scanS3 };