# Changelog

## v2.2.0 - detection-validation fixes (2026-10-31)

Fixes from the detection-validation audit of v2.1.4. Every change below has tests (positive, negative and
error/unknown cases) in `tests/test_v22_fixes.py`. Live AWS behaviour is still **unverified**: all AWS testing uses
synthetic responses (botocore `Stubber` and fake sessions), not a real account.

### Detection (AWS collector + rules)
- **IAM reads real policy documents** (`AWS-IAM-005`, new `shieldiq/rules/iam_policy.py`). The collector reads
  attached managed policies (GetPolicy -> GetPolicyVersion, default version), inline user / group / role policies,
  and group membership. The rule flags full admin (`Action "*"` on `Resource "*"`) and common privilege-escalation
  permissions: iam:CreatePolicyVersion, SetDefaultPolicyVersion, Attach{User,Group,Role}Policy,
  Put{User,Group,Role}Policy, AddUserToGroup, UpdateAssumeRolePolicy, CreateAccessKey, Create/UpdateLoginProfile,
  and iam:PassRole + ec2:RunInstances / lambda:CreateFunction / cloudformation:CreateStack /
  glue:CreateDevEndpoint / datapipeline:CreatePipeline. Wildcards (`iam:*`) and NotAction are handled, and
  unconditional Deny statements on `*` are honoured. The `AdministratorAccess` name match is kept. A principal is
  only reported "scoped" when every one of its policies was read. Otherwise it is unknown, and a known admin is
  still reported. *Not evaluated:* permission boundaries, SCPs, session/resource policies and conditions (a
  conditional grant is still reported and labelled as conditional).
- **Pagination everywhere.** Every list/describe call goes through boto3 paginators (`_pages`).
- **All regions.** EC2, RDS, KMS and GuardDuty are read in every enabled region (DescribeRegions, opted-in only),
  or in a per-integration region list. If region discovery is denied, the scan falls back to the home region and
  is marked partial. Resources carry their `region`.
- **S3:** account-level Block Public Access (s3control GetPublicAccessBlock) is combined with bucket-level BPA
  before a bucket is called non-compliant or public. IgnorePublicAcls neutralises public ACL grants, and
  RestrictPublicBuckets neutralises public policies. `AuthenticatedUsers` ACL grants now count as public. An
  unreadable account-level setting is unknown, not "off".
- **EC2 security groups** (`AWS-EC2-001`): risky ports widened to admin plus datastore/search/cache ports (22, 23,
  3389, 5900, 445, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 9300, 5601, 11211, 5984, 9042, 2375, 2376). This
  covers ranges, all-ports rules and IPv6 `::/0`. ICMP rules are no longer read as ports.
- **EC2 instances:** terminated and shutting-down instances are skipped. A volume missing from the (complete)
  volume listing is now unknown instead of "unencrypted".
- **GuardDuty:** the detector status is read (GetDetector). A suspended detector (Status=DISABLED) counts as not
  enabled, and an unreadable status is unknown. Results are per region.
- **CloudTrail:** passes only if ONE trail is multi-region AND logging AND log-file-validated. Properties of
  different trails are no longer combined.

### Findings lifecycle
- A rule that crashes no longer yields a fake "passed" result. It yields no results plus an error. The scan is
  marked **partial**, the error is named in the run, and that rule's existing findings stay open
  ("Unverified: ... rule error").
- A finding is auto-resolved only if this scan evaluated that resource for that rule and it passed. A resource
  that is no longer listed is resolved ("no longer present") only after a complete scan: no read errors and no
  rule errors.

### App security
- **Demo seeding is OFF by default** (`SHIELDIQ_SEED_DEMO=1` opts in). Demo credentials and demo content on the
  login page, landing page and guides appear only in demo mode, even if a demo account exists in the database.
- `user_loader` rejects inactive users (defence in depth). Note: v2.1.4 already blocked disabled users through
  Flask-Login 0.6's `UserMixin.is_authenticated`. The audit's "session keeps working" result was a test-harness
  artefact (a shared app context); see the test evidence.
- **Generated fix scripts are quoted.** Resource values are `shlex.quote`d in shell scripts, escaped for HCL in
  Terraform, and flattened (no control characters or newlines) in comments and YAML/code snippets. A test runs a
  generated script with a hostile bucket name against a stub `aws` binary and checks nothing is executed.
- S3 fix commands use the **bucket name**, not the ARN.
- **Evidence labels:** every finding carries `evidence_origin` in the API and the UI (live-scan = verified; demo,
  snapshot and uploaded files = "not verified scanner evidence", with demo marked DEMO DATA). Copilot output is
  labelled (`ai_generated`, `verified_evidence: false`, `disclaimer`) in the API, the chat UI and the finding
  page. The Copilot still cannot create, confirm or resolve findings.
- **AWS CLI profiles:** the free-text profile field is gone. Only profiles listed in
  `SHIELDIQ_ALLOWED_AWS_PROFILES` can be chosen (default: none). This is checked at creation and again at every
  scan. The collector never falls back to boto3's default credential chain, so it never uses the server's own
  credentials. Region names are validated.

### Test changes to existing tests (because behaviour changed on purpose)
- `tests/conftest.py`: the `demo` fixture switches demo mode on (`SEED_DEMO=True`), since demo content is now
  shown only in demo mode.
- `tests/test_collector_errors.py`: the fake session accepts `region_name`, and the clean-account fixture answers
  the three new read-only calls (DescribeRegions, s3control GetPublicAccessBlock, GuardDuty GetDetector).
  No assertions were changed.

### Results (real runs, synthetic AWS)
- Test suite: 119 passed (v2.1.4) -> **193 passed** (119 existing + 74 new) in v2.2.0.
- Audit detection matrix (78 cases): **64/78 -> 77/78**. The one remaining miss is out of scope for this
  release: a world-open SSH rule split into `0.0.0.0/1` + `128.0.0.0/1` is not recognised as internet-wide.
