// src/scanners/ec2Scanner.js
// Returns all security groups in the configured region, fully paginated.
// Each object includes IpPermissions[].Ipv6Ranges[] for IPv6 CIDR detection.

const { DescribeSecurityGroupsCommand } = require("@aws-sdk/client-ec2");
const { ec2 } = require("../config/aws");

async function scanEC2() {
  const groups = [];
  let nextToken;

  do {
    const resp = await ec2.send(
      new DescribeSecurityGroupsCommand({ NextToken: nextToken, MaxResults: 100 })
    );
    groups.push(...(resp.SecurityGroups || []));
    nextToken = resp.NextToken;
  } while (nextToken);

  return groups;
}

module.exports = { scanEC2 };
