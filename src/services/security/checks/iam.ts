/** IAM account hygiene: root MFA, password policy, user MFA and key age. */

import {
  IAMClient,
  GetAccountSummaryCommand,
  GetAccountPasswordPolicyCommand,
  ListUsersCommand,
  ListMFADevicesCommand,
  ListAccessKeysCommand,
  type GetAccountSummaryCommandOutput,
  type GetAccountPasswordPolicyCommandOutput,
  type ListUsersCommandOutput,
  type ListMFADevicesCommandOutput,
  type ListAccessKeysCommandOutput,
  type User,
} from '@aws-sdk/client-iam';

import { classifyAwsError } from '../../../util/errors.js';
import { mapWithConcurrency } from '../../../util/async.js';
import { GLOBAL_SCOPE } from '../../../aws/regions.js';
import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor } from '../check-utils.js';
import type { EvaluationIssue } from '../../types.js';

const CHECK_ID = 'iam-account-hygiene';
const MAX_USERS = 200;
const ACCESS_KEY_MAX_AGE_DAYS = 90;

const DAY_MS = 24 * 60 * 60 * 1000;

export function accessKeyAgeDays(createDate: Date | undefined, now = new Date()): number {
  if (!createDate) return 0;
  return Math.floor((now.getTime() - createDate.getTime()) / DAY_MS);
}

export const iamHygieneCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'IAM account hygiene',
  service: 'IAM',
  scope: 'global',
  description:
    'Checks root MFA, the account password policy, IAM users without MFA, and access keys older than 90 days.',
  requiredPermissions: [
    'iam:GetAccountSummary',
    'iam:GetAccountPasswordPolicy',
    'iam:ListUsers',
    'iam:ListMFADevices',
    'iam:ListAccessKeys',
  ],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('iam', IAMClient, {
      profile: context.profile,
      region: GLOBAL_SCOPE,
    });
    const findings: CheckResult['findings'] = [];
    const issues: EvaluationIssue[] = [];
    const accountId = context.accountId ?? 'account';

    try {
      const summary = await client.send<GetAccountSummaryCommandOutput>(
        new GetAccountSummaryCommand({}),
        { section: context.section }
      );
      const map = summary.SummaryMap ?? {};
      if (map.AccountMFAEnabled === 0) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: GLOBAL_SCOPE,
            title: 'The root user does not have MFA enabled',
            severity: 'critical',
            resourceType: 'AWS::IAM::RootUser',
            resourceId: accountId,
            source: 'IAM',
            discriminator: 'root-mfa',
            evidence: { accountMFAEnabled: map.AccountMFAEnabled },
            why: 'The root user can do anything in the account and cannot be restricted by IAM policies. Without MFA a leaked root password is a full account compromise.',
            recommendation:
              'Sign in as root and enable a hardware or virtual MFA device in the IAM console.',
          })
        );
      }
      if ((map.AccountAccessKeysPresent ?? 0) > 0) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: GLOBAL_SCOPE,
            title: 'The root user has active access keys',
            severity: 'critical',
            resourceType: 'AWS::IAM::RootUser',
            resourceId: accountId,
            source: 'IAM',
            discriminator: 'root-access-keys',
            evidence: { accountAccessKeysPresent: map.AccountAccessKeysPresent },
            why: 'Root access keys grant unrestricted programmatic access and cannot be scoped down.',
            recommendation:
              'Delete the root access keys in the IAM console and use IAM roles or IAM Identity Center instead.',
          })
        );
      }
    } catch (error) {
      issues.push(
        issueFor(context, error, {
          service: 'IAM',
          check: CHECK_ID,
          requiredPermission: 'iam:GetAccountSummary',
          detail: 'reading the account summary',
        })
      );
    }

    try {
      const policy = await client.send<GetAccountPasswordPolicyCommandOutput>(
        new GetAccountPasswordPolicyCommand({}),
        { section: context.section }
      );
      const passwordPolicy = policy.PasswordPolicy ?? {};
      const weaknesses: string[] = [];
      if ((passwordPolicy.MinimumPasswordLength ?? 0) < 14)
        weaknesses.push('minimum length below 14');
      if (!passwordPolicy.RequireSymbols) weaknesses.push('symbols not required');
      if (!passwordPolicy.RequireNumbers) weaknesses.push('numbers not required');
      if (!passwordPolicy.RequireUppercaseCharacters) weaknesses.push('uppercase not required');
      if (!passwordPolicy.RequireLowercaseCharacters) weaknesses.push('lowercase not required');
      if (!passwordPolicy.PasswordReusePrevention) weaknesses.push('password reuse not prevented');

      if (weaknesses.length > 0) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: GLOBAL_SCOPE,
            title: 'The IAM password policy is weaker than recommended',
            severity: 'low',
            resourceType: 'AWS::IAM::PasswordPolicy',
            resourceId: accountId,
            source: 'IAM',
            discriminator: 'password-policy',
            evidence: { passwordPolicy, weaknesses },
            why: 'A weak console password policy makes credential stuffing and brute force attacks more likely to succeed.',
            recommendation:
              'Strengthen the account password policy in the IAM console, or move console access to IAM Identity Center.',
          })
        );
      }
    } catch (error) {
      const classified = classifyAwsError(error);
      if (classified.kind === 'not-found') {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: GLOBAL_SCOPE,
            title: 'No IAM password policy is configured',
            severity: 'low',
            resourceType: 'AWS::IAM::PasswordPolicy',
            resourceId: accountId,
            source: 'IAM',
            discriminator: 'password-policy-missing',
            evidence: { passwordPolicy: null },
            why: 'Without an explicit policy, IAM console users can set short, simple passwords.',
            recommendation:
              'Configure a password policy in the IAM console, or manage console access through IAM Identity Center.',
          })
        );
      } else {
        issues.push(
          issueFor(context, error, {
            service: 'IAM',
            check: CHECK_ID,
            requiredPermission: 'iam:GetAccountPasswordPolicy',
            detail: 'reading the account password policy',
          })
        );
      }
    }

    let users: User[] = [];
    let truncated = false;
    try {
      let marker: string | undefined;
      do {
        const output = await client.send<ListUsersCommandOutput>(
          new ListUsersCommand({ MaxItems: 100, ...(marker ? { Marker: marker } : {}) }),
          { section: context.section }
        );
        users.push(...(output.Users ?? []));
        marker = output.IsTruncated ? output.Marker : undefined;
      } while (marker && users.length < MAX_USERS);
      if (users.length > MAX_USERS) {
        users = users.slice(0, MAX_USERS);
        truncated = true;
      }
    } catch (error) {
      issues.push(
        issueFor(context, error, {
          service: 'IAM',
          check: CHECK_ID,
          requiredPermission: 'iam:ListUsers',
          detail: 'listing IAM users',
        })
      );
      return { findings, issues, evaluated: false };
    }

    const now = new Date();
    let mfaDenied = false;
    let keysDenied = false;

    await mapWithConcurrency(users, 5, async (user) => {
      if (!user.UserName) return;

      if (user.PasswordLastUsed || user.CreateDate) {
        try {
          const devices = await client.send<ListMFADevicesCommandOutput>(
            new ListMFADevicesCommand({ UserName: user.UserName }),
            { section: context.section }
          );
          if ((devices.MFADevices ?? []).length === 0 && user.PasswordLastUsed) {
            findings.push(
              buildFinding({
                context,
                checkId: CHECK_ID,
                region: GLOBAL_SCOPE,
                title: `IAM user ${user.UserName} uses the console without MFA`,
                severity: 'high',
                resourceType: 'AWS::IAM::User',
                resourceId: user.UserName,
                ...(user.Arn ? { resourceArn: user.Arn } : {}),
                source: 'IAM',
                discriminator: 'user-mfa',
                evidence: {
                  userName: user.UserName,
                  passwordLastUsed: user.PasswordLastUsed,
                  createdAt: user.CreateDate,
                  mfaDevices: 0,
                },
                why: 'This user has signed in to the console but has no MFA device, so a stolen password is enough to authenticate.',
                recommendation:
                  'Require MFA for this user in the IAM console, or move console access to IAM Identity Center.',
              })
            );
          }
        } catch (error) {
          if (!mfaDenied) {
            mfaDenied = true;
            issues.push(
              issueFor(context, error, {
                service: 'IAM',
                check: CHECK_ID,
                requiredPermission: 'iam:ListMFADevices',
                detail: 'listing MFA devices',
              })
            );
          }
        }
      }

      try {
        const keys = await client.send<ListAccessKeysCommandOutput>(
          new ListAccessKeysCommand({ UserName: user.UserName }),
          { section: context.section }
        );
        for (const key of keys.AccessKeyMetadata ?? []) {
          if (key.Status !== 'Active') continue;
          const age = accessKeyAgeDays(key.CreateDate, now);
          if (age < ACCESS_KEY_MAX_AGE_DAYS) continue;
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              region: GLOBAL_SCOPE,
              title: `IAM user ${user.UserName} has an access key that is ${age} days old`,
              severity: age >= 365 ? 'medium' : 'low',
              resourceType: 'AWS::IAM::AccessKey',
              resourceId: `${user.UserName}/${key.AccessKeyId ?? 'unknown'}`,
              source: 'IAM',
              discriminator: `access-key-${key.AccessKeyId ?? ''}`,
              evidence: {
                userName: user.UserName,
                accessKeyId: key.AccessKeyId,
                createdAt: key.CreateDate,
                ageDays: age,
                status: key.Status,
              },
              why: 'Long-lived static credentials accumulate exposure; the older a key is, the more places it may have leaked to.',
              recommendation:
                'Rotate or delete the key in the IAM console, and prefer short-lived role credentials or IAM Identity Center where possible.',
            })
          );
        }
      } catch (error) {
        if (!keysDenied) {
          keysDenied = true;
          issues.push(
            issueFor(context, error, {
              service: 'IAM',
              check: CHECK_ID,
              requiredPermission: 'iam:ListAccessKeys',
              detail: 'listing access keys',
            })
          );
        }
      }
    });

    return issues.length > 0
      ? { findings, issues, evaluated: false, resourcesEvaluated: users.length, truncated }
      : evaluated({ findings, resourcesEvaluated: users.length, truncated });
  },
};
