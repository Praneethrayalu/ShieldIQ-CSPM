# ShieldIQ IAM validation kit

Compare ShieldIQ's IAM results with AWS's own policy simulator in a **dedicated, isolated AWS test account**.

> Status: this kit has been run end-to-end **only against the in-memory mock** (`python validation/shieldiq_validate.py mock`).
> **Live AWS validation has not been executed.**

## 1. Prepare the test account (once)

1. Create a **new AWS account used for nothing else** (e.g. in a sandbox OU of your organization). Never use a
   production account, the organization management account, or an account with real workloads. The kit refuses the
   management account and any account whose alias contains `prod`.
2. Optional but recommended: a budget alarm, and an SCP on the sandbox OU that denies `iam:CreateAccessKey`,
   `iam:CreateLoginProfile` for `arn:aws:iam::*:user/shieldiq-validation/*`.
3. Create two IAM roles (or SSO permission sets) for the validator:
   - **setup role**: attach `policies/shieldiq-validation-setup-policy.json`. It can create/delete only resources under
     the IAM path `/shieldiq-validation/`, can attach only the validation policies and `AdministratorAccess`, and is
     explicitly denied from creating any credential (access keys, passwords, SSH keys, certificates).
   - **scanner role**: attach the AWS-managed `SecurityAudit` policy plus `policies/shieldiq-scanner-extra-policy.json`
     (simulator, authorization details, Organizations read, bucket policies). Read-only.
   (One role with both is fine for a sandbox.)
4. Configure a CLI profile for it and confirm: `aws sts get-caller-identity --profile shieldiq-sandbox`.

## 2. What gets created

`python validation/shieldiq_validate.py plan` prints it. In short (all under `/shieldiq-validation/`, named `siqv-*`,
tagged `shieldiq-validation=true`, **no credentials of any kind**):

| Principal | Misconfiguration it represents |
|---|---|
| siqv-admin | inline `*:*` (full admin) |
| siqv-dev (group siqv-devs) | group-inherited, scoped S3 + `ec2:Describe*` (negative case) |
| siqv-passrole | `iam:PassRole` on an admin role + `ec2:RunInstances` (escalation) |
| siqv-bounded | inline `iam:*` neutralised by an S3-only permissions boundary (negative case) |
| siqv-denied | `Allow *` + group explicit `Deny iam:*` |
| siqv-mfa | `iam:CreatePolicyVersion` on its own policy only with MFA (conditional → Indeterminate) |
| siqv-reader | `s3:GetObject` with `NotResource` excluding a secret bucket |
| siqv-assumer → role siqv-ops | assume a role that can attach policies to itself |
| role siqv-ec2-admin | trusted by ec2.amazonaws.com, AdministratorAccess (PassRole target) |

Roles trust only these credential-less users or an AWS service, so nobody can actually use them. No S3 buckets or other
resources are created.

## 3. Run

```bash
export SHIELDIQ_VALIDATION_ACCOUNT=123456789012      # must equal --account-id and the credentials' account
P=shieldiq-sandbox; A=$SHIELDIQ_VALIDATION_ACCOUNT
python validation/shieldiq_validate.py setup   --profile $P --account-id $A           # dry run
python validation/shieldiq_validate.py setup   --profile $P --account-id $A --apply   # create
sleep 20                                                                               # IAM is eventually consistent
python validation/shieldiq_validate.py run     --profile $P --account-id $A --out validation/out-live
python validation/shieldiq_validate.py cleanup --profile $P --account-id $A           # dry run
python validation/shieldiq_validate.py cleanup --profile $P --account-id $A --apply   # delete
```

Or as one test: `SHIELDIQ_LIVE_AWS_VALIDATION=1 AWS_PROFILE=$P pytest tests/integration -v` (always cleans up).

## 4. Read the report

`validation_report.md` / `.json`: one row per check with **expected**, **ShieldIQ actual**, **AWS simulator**
(`allowed` / `implicitDeny` / `explicitDeny`), **comparison** and **PASS/FAIL**, then data-source completeness and
limitations. A `mismatch` is a real disagreement between ShieldIQ and AWS and should be investigated (file the case).
`shieldiq-indeterminate` is expected for D09: the simulator treats a missing MFA key as "not present" (deny) while
ShieldIQ reports that the answer depends on the request.

## 5. Cleanup safety

Cleanup lists only `/shieldiq-validation/` resources; users and roles must also carry the tag, otherwise they are
skipped and reported. It removes group memberships, inline and attached policies, boundaries and non-default policy
versions before deleting. Dry run unless `--apply`.

## 6. Mock run (no AWS)

`python validation/shieldiq_validate.py mock --out validation/out` runs guard → setup → ShieldIQ collection and
evaluation → comparison → report → cleanup against `mock_aws.py`. The mock's simulator answers are the expectations
written in `cases.json`, so a mock PASS shows the kit works; it is **not** evidence of agreement with AWS.
