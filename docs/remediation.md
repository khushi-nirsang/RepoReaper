# Remediation

Deleting a value from the latest file does not revoke it and does not remove earlier Git objects.

## 1. Contain The Credential

Rotate or revoke through the credential provider first. Replace the value in legitimate deployments, CI variables, secret stores, and developer environments. Review provider audit logs and scope for suspicious use. RepoReaper cannot perform or confirm any of these provider actions.

Use the redacted preview, detector, path, and commit evidence to identify the credential through an authorized provider console or internal inventory. Do not copy a raw value into an issue or remediation report.

## 2. Remove Current Source

Remove the credential from tracked source and any included untracked files. Replace it with an environment/secret-manager reference. Scan again with current scope:

```sh
reporeaper scan . --include-untracked --fail-on high --fail-scope current
```

An ignored untracked file is not included by `--include-untracked`; inspect authorized ignored deployment/configuration locations separately when relevant.

## 3. Assess Reachable And Residual History

Create a restricted broad JSON baseline before history cleanup:

```sh
reporeaper scan . --include-untracked --all-refs --reflogs --unreachable --format json --output baseline.json
```

Review branch, tag, remote-tracking, reflog, unreachable-object, and timeline evidence. Fetch any authorized missing history first. Scan Git LFS objects and submodules separately because RepoReaper does not materialize them.

## 4. Decide Whether To Rewrite

Revocation is the primary control. History rewriting may still be required by policy or to reduce accidental redistribution, but it is disruptive and cannot erase every clone, fork, cache, artifact, log, backup, or provider record.

RepoReaper never rewrites history. If an authorized rewrite is required:

- coordinate with repository owners and collaborators;
- protect backups and required refs;
- use an established history-rewriting tool;
- review tags, release artifacts, CI caches, package registries, mirrors, and documentation;
- force-push only after explicit team approval;
- tell collaborators how to discard contaminated clones rather than merging old history back.

Do not run reflog expiration or garbage collection merely to make a local verification pass. Those actions destroy forensic evidence and do not revoke a credential.

## 5. Verify Local Evidence

After authorized cleanup:

```sh
reporeaper verify . --baseline baseline.json
reporeaper verify . --baseline baseline.json --format json --output verification.json
```

Interpret outcomes conservatively:

- exit `0`: baseline fingerprints were not observed under complete reproducible local scope;
- exit `1`: at least one baseline fingerprint remains;
- exit `3`: scope, warnings, objects, or detector definitions prevent a conclusion.

Credential rotation always remains unconfirmed, and no local result proves remote deletion. Preserve verification output as restricted incident evidence according to the organization's retention policy.

## 6. Prevent Recurrence

Install staged protection where the repository's hook policy permits it:

```sh
reporeaper protect install
```

Add a CI severity/scope gate, keep the active detector/configuration reviewed, and prefer narrow fingerprint/path allowlists. The hook fails closed if supported staged content cannot be completely inspected; raise `scan.max_file_size` only after intentionally reviewing a legitimate large staged object.

If CI uses `scan --baseline` to suppress accepted findings, review and protect that JSON as security metadata. Baseline suppression is only new-finding triage; continue to use the broad `verify --baseline` workflow for incident cleanup.
