/** Security group rules that expose resources to the public internet. */

import {
  DescribeSecurityGroupsCommand,
  EC2Client,
  type DescribeSecurityGroupsCommandOutput,
  type SecurityGroup,
  type IpPermission,
} from '@aws-sdk/client-ec2';

import {
  buildFinding,
  type CheckContext,
  type CheckResult,
  type SecurityCheck,
  type Severity,
} from '../types.js';
import { evaluated, issueFor, notEvaluated } from '../check-utils.js';

const CHECK_ID = 'security-group-open-to-world';

/** Ports whose exposure to the internet is treated as critical. */
export const SENSITIVE_PORTS: Readonly<Record<number, string>> = Object.freeze({
  20: 'FTP data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  135: 'RPC',
  137: 'NetBIOS',
  139: 'NetBIOS',
  445: 'SMB',
  1433: 'Microsoft SQL Server',
  1521: 'Oracle DB',
  2375: 'Docker (unencrypted)',
  2376: 'Docker',
  3306: 'MySQL / MariaDB',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5601: 'Kibana',
  5984: 'CouchDB',
  6379: 'Redis',
  7001: 'Cassandra',
  8020: 'HDFS',
  9200: 'Elasticsearch',
  9300: 'Elasticsearch transport',
  11211: 'Memcached',
  27017: 'MongoDB',
  27018: 'MongoDB',
});

const OPEN_IPV4 = '0.0.0.0/0';
const OPEN_IPV6 = '::/0';

export interface OpenRule {
  protocol: string;
  fromPort?: number;
  toPort?: number;
  cidr: string;
  severity: Severity;
  reason: string;
  sensitivePorts: string[];
}

function portsInRange(from: number | undefined, to: number | undefined): number[] {
  if (from === undefined || to === undefined) return [];
  if (to - from > 1024) return []; // Treat very wide ranges via the "all ports" path.
  const ports: number[] = [];
  for (let port = from; port <= to; port += 1) ports.push(port);
  return ports;
}

/** Pure rule analysis, exported so it can be tested without AWS. */
export function analyseRule(permission: IpPermission): OpenRule[] {
  const openCidrs: string[] = [
    ...(permission.IpRanges ?? [])
      .map((range) => range.CidrIp)
      .filter((cidr): cidr is string => cidr === OPEN_IPV4),
    ...(permission.Ipv6Ranges ?? [])
      .map((range) => range.CidrIpv6)
      .filter((cidr): cidr is string => cidr === OPEN_IPV6),
  ];
  if (openCidrs.length === 0) return [];

  const protocol = permission.IpProtocol ?? '-1';
  const allProtocols = protocol === '-1';
  const from = permission.FromPort;
  const to = permission.ToPort;
  const allPorts =
    allProtocols || (from === 0 && to === 65535) || (from === undefined && to === undefined);

  return openCidrs.map((cidr) => {
    if (allPorts) {
      return {
        protocol: allProtocols ? 'all' : protocol,
        ...(from !== undefined ? { fromPort: from } : {}),
        ...(to !== undefined ? { toPort: to } : {}),
        cidr,
        severity: 'critical' as Severity,
        reason: allProtocols
          ? 'All protocols and all ports are reachable from the entire internet.'
          : 'All ports for this protocol are reachable from the entire internet.',
        sensitivePorts: [],
      };
    }

    const ports = portsInRange(from, to);
    const sensitive = ports
      .filter((port) => port in SENSITIVE_PORTS)
      .map((port) => `${port} (${SENSITIVE_PORTS[port]})`);
    const wideRange = from !== undefined && to !== undefined && to - from > 1024;

    return {
      protocol,
      ...(from !== undefined ? { fromPort: from } : {}),
      ...(to !== undefined ? { toPort: to } : {}),
      cidr,
      severity: (sensitive.length > 0 ? 'critical' : wideRange ? 'high' : 'high') as Severity,
      reason:
        sensitive.length > 0
          ? `Administrative or database ports are reachable from the entire internet: ${sensitive.join(', ')}.`
          : 'This port range is reachable from the entire internet.',
      sensitivePorts: sensitive,
    };
  });
}

function describePorts(rule: OpenRule): string {
  if (rule.protocol === 'all') return 'all ports';
  if (rule.fromPort === undefined || rule.toPort === undefined) return 'unspecified ports';
  return rule.fromPort === rule.toPort
    ? `port ${rule.fromPort}`
    : `ports ${rule.fromPort}-${rule.toPort}`;
}

export const securityGroupCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'Security groups open to the internet',
  service: 'Security Groups',
  scope: 'regional',
  description:
    'Flags inbound security group rules that allow 0.0.0.0/0 or ::/0, with critical severity for administrative and database ports or unrestricted access.',
  requiredPermissions: ['ec2:DescribeSecurityGroups'],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('ec2', EC2Client, {
      profile: context.profile,
      region: context.region,
    });

    const groups: SecurityGroup[] = [];
    let token: string | undefined;
    try {
      do {
        const output = await client.send<DescribeSecurityGroupsCommandOutput>(
          new DescribeSecurityGroupsCommand({
            MaxResults: 1000,
            ...(token ? { NextToken: token } : {}),
          }),
          { section: context.section }
        );
        groups.push(...(output.SecurityGroups ?? []));
        token = output.NextToken;
      } while (token);
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'Security Groups',
          check: CHECK_ID,
          requiredPermission: 'ec2:DescribeSecurityGroups',
        }),
      ]);
    }

    const findings = groups.flatMap((group) =>
      (group.IpPermissions ?? []).flatMap((permission) =>
        analyseRule(permission).map((rule) =>
          buildFinding({
            context,
            checkId: CHECK_ID,
            title: `Security group ${group.GroupId} allows ${describePorts(rule)} from ${rule.cidr}`,
            severity: rule.severity,
            resourceType: 'AWS::EC2::SecurityGroup',
            resourceId: group.GroupId ?? 'unknown',
            source: 'Security Groups',
            discriminator: `${rule.protocol}:${rule.fromPort ?? '*'}-${rule.toPort ?? '*'}:${rule.cidr}`,
            evidence: {
              groupId: group.GroupId,
              groupName: group.GroupName,
              vpcId: group.VpcId,
              protocol: rule.protocol,
              fromPort: rule.fromPort,
              toPort: rule.toPort,
              cidr: rule.cidr,
              sensitivePorts: rule.sensitivePorts,
              description: group.Description,
            },
            why: rule.reason,
            recommendation:
              'Review this rule in the EC2 console and restrict the source to the specific CIDR ranges, prefix lists or security groups that need access. ' +
              'This dashboard never modifies security groups.',
          })
        )
      )
    );

    return evaluated({ findings, resourcesEvaluated: groups.length });
  },
};
