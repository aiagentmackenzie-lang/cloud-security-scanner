// src/config/aws.js
// AWS SDK client factory. Credentials resolved via default provider chain — never hardcoded.
// Chain order: AWS_ACCESS_KEY_ID/SECRET → ~/.aws/credentials → IAM role → SSO session.

const { S3Client }  = require("@aws-sdk/client-s3");
const { IAMClient } = require("@aws-sdk/client-iam");
const { EC2Client } = require("@aws-sdk/client-ec2");

const REGION = process.env.AWS_REGION || "us-east-1";
const clientConfig = { region: REGION };

const s3  = new S3Client(clientConfig);
const iam = new IAMClient(clientConfig);
const ec2 = new EC2Client(clientConfig);

module.exports = { s3, iam, ec2, REGION };
