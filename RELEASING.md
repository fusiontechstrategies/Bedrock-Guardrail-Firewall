# Release process

Bedrock Guardrail Firewall releases must come from a reviewed, fully tested, signed commit on protected `main`. Owner approval of the protected `release` environment authorizes attestation and draft creation. Publishing the draft and a separate manual main-branch publish run, followed by `pypi` approval, authorize package publication. The repository does not use a long-lived PyPI password or API token.

## One-time trusted-publisher setup

Before the first PyPI release:

1. Secure the PyPI maintainer account with two-factor authentication and store its recovery codes outside the repository.
2. Register a pending PyPI trusted publisher for project `bedrock-guardrail-firewall`, GitHub owner `fusiontechstrategies`, repository `Bedrock-Guardrail-Firewall`, workflow `publish.yml`, and environment `pypi`.
3. Configure the GitHub `release` and `pypi` environments with required owner review and a custom deployment branch policy allowing only the branch `main`, with no tag policy. Preserve the existing `pypi` reviewer. Environment approval and tag creation are separate trusted maintainer actions.
4. Do not create a repository PyPI token. Trusted publishing uses a short-lived, job-scoped OpenID Connect credential.

The package name must be checked again immediately before setup and publication. An unavailable or disputed namespace is a release blocker.

## Prepare the release candidate

1. Start from current protected `main`.
2. Replace the development version with the approved stable version in project metadata, runtime metadata, installed-package validation, and continuous integration.
3. Move the release notes out of `Unreleased`, add the release date and comparison link, and update installation and testing documentation.
4. Run the complete supported Python matrix, optional integration tests, quality checks, security scans, dependency audits, package tests, and sanitized demo.
5. Set `SOURCE_DATE_EPOCH` to the release commit time, build distributions twice into separate empty directories, normalize each source archive with `scripts/normalize_sdist.py`, require identical filenames and bytes, and run `twine check`.
6. Confirm the checked-out commit matches the release event, then run `scripts/prepare_release_evidence.py` with the proposed tag and exact 40-character commit ID. It rejects development versions, mismatched identities, unsafe archive members, unexpected distribution files, incomplete metadata, and an existing evidence directory.
7. Inspect both archives, the SPDX 2.3 dependency SBOM, `release-evidence.json`, and `SHA256SUMS.txt` before approval.

The `Release candidate` entrypoint is `repository_dispatch` with event type `release-candidate` and data fields `release_tag` and `source_commit`. GitHub resolves that event's workflow from the default branch, never from the selected tag or a caller-selected workflow ref. Its resolver authenticates the immutable remote tag, signed source commit and protected-main ancestry before the isolated read-only build. It has no release-write, OIDC or attestation permission. A successful candidate starts default-main promotion verification, but attestation and draft creation still require `release` owner approval. Do not invoke the dispatch as part of security maintenance.

## Publish

1. Merge only after branch protections and every required check pass.
2. Issue the tag through the protected tag workflow below. Security maintenance does not create tags. Existing immutable tags can be selected as data.
3. When an approved immutable tag exists, explicitly request the default-main candidate with its exact tag and commit data. The `Promote verified release candidate` workflow authenticates the signed main producer run and unique immutable artifact ID, then independently authenticates candidate tag/source claims against the immutable remote tag and protected-main history. It checks out selected source strictly as data and reconstructs all five assets with the verifier pinned to the trusted workflow commit. Approve `release` only after this verification, then wait for attestation and verified draft creation.
4. Confirm the draft contains exactly five assets: the wheel, source distribution, SPDX 2.3 dependency SBOM, `SHA256SUMS.txt`, and `release-evidence.json`. Review their provenance and contents along with the release notes.
5. Publish the GitHub release only after explicit release approval.
6. Start `Publish package` manually on `main` with the approved tag, exact source commit and exact promotion workflow commit recorded in its provenance. The verify job checks signed protected-main ancestry, immutable tag binding, published non-prerelease status, exact assets and trusted-main signer provenance, then independently reconstructs the evidence. Approve `pypi` only after these checks.

The trusted promotion workflow attests the exact reconstructed five-file payload. Its attestation identifies the protected-main promotion workflow commit, rather than pretending the tagged producer is the trusted signer. Independently reconstructed evidence binds the distributions to the selected tag and source commit. Draft creation never replaces a prior release; failed verification cleans up only the immutable release ID returned by that invocation, and a cleanup failure requires owner review. Publication rechecks the attestation and final distribution hashes against the verified manifest before trusted publishing. An existing PyPI version is not skipped silently.

The protected-main reviewer, environment approver and repository settings administrator remain trusted authorities. Source workflow permission declarations cannot globally cap the authority of arbitrary newly tagged YAML. The default tag creation freeze and the no-bypass update and deletion rules protect every version. The separate release and registry environments still use their existing maintainer approvals. The promotion path refuses source outside signed protected-main history. Selected source and candidate artifacts never supply the executing verifier, dependency lock or privileged Python import path. All verifier environment bootstrapping uses isolated Python module resolution.

## Issue a version tag

Use a private, dedicated GitHub App installed only on this repository. Grant Contents write and the required Metadata read permission. The App needs no administration or workflow-edit permission. Store its client ID as `BEDROCK_TAG_APP_CLIENT_ID` and its key as `BEDROCK_TAG_APP_PRIVATE_KEY` in the separate `release-tag` environment. That environment must require the repository owner's approval, allow only the branch `main`, and disallow administrator overrides. Set its `BEDROCK_APPROVED_RELEASE_TAG` and `BEDROCK_APPROVED_RELEASE_COMMIT` variables to the exact reviewed values.

1. After the verified merge and green main checks, create an active **creation-only** ruleset named `Bedrock authorized tag vX.Y.Z` for the literal `refs/tags/vX.Y.Z`. Read it back with an administrative credential and confirm that the dedicated App is the sole listed actor. GitHub omits bypass actors from ordinary ruleset reads. Check the no-bypass update and deletion ruleset with the same credential.
2. Only after that exact rule is active, exclude the literal tag from the blanket creation freeze. Leave every other version covered by the blanket no-bypass rule.
3. Dispatch `release-tag.yml` on `main` with the exact approved tag and commit. Review the read-only verification job, approve the `release-tag` job, and confirm the ref points to the approved commit. The workflow refuses to replace a ref.
4. On success, failure, or cancellation, restore the blanket rule to cover the literal tag again. Read back both no-bypass rules before removing the exact-version creation rule. Remove the environment's one-release approval values and revoke the App key if it was issued for this release only.
5. Dispatch the existing release candidate separately. The tag issuer does not attest, create a public release, or upload to PyPI.

## Post-publication verification

1. Confirm the GitHub workflow and PyPI attestations are successful.
2. Download every GitHub asset and recompute `SHA256SUMS.txt` independently.
3. Create a clean isolated environment and install the exact version from PyPI.
4. Verify distribution metadata, the console version, the offline doctor command, packaged policies, and the sanitized demo.
5. Confirm no unexpected dependency is installed for the standard-library-only core.
6. Link the verified PyPI project from the README and GitHub release.
7. Record the tag, commit, hashes, attestation links, test evidence, and publication time.

If any check fails, stop publication or publish a new version after correction. Never rebuild or replace an already published version.

### Complete source archive coverage

Trusted evidence validation interprets only static `include` and approved `recursive-include` manifest rules. It compares every source-controlled file byte, the exact regular-file member set, portable names, and approved file modes. Generated PKG-INFO, egg-info metadata, SOURCES.txt, and setup.cfg are reconstructed from reviewed static project declarations without importing the selected source or invoking its build backend. Only explicitly enumerated backend newline forms are accepted for generated metadata; source-controlled files have no newline exception. Changes to manifest syntax, project metadata, package layout, or backend output require a corresponding reviewed verifier change. Candidate archive metadata cannot define the expected source set.

The evidence generator validates immutable bounded artifact snapshots and computes every distribution digest and size from those same bytes. It checks the distribution paths still contain those snapshots before completing, so a concurrent replacement cannot acquire a digest for unvalidated content. Subsequent promotion still requires the recorded digests and authenticated attestations. Source archives must have one complete gzip stream and one complete tar archive without hidden trailing content. Unknown gzip flags and tar extension metadata are rejected. Run the pinned normalizer before verification on every platform. All tar ownership IDs and timestamps are zero, owner/group names are empty, directory modes are 0755, file modes are 0644 (0755 only for a reviewed executable), and extension records are rejected. Gzip retains the supplied build epoch for reproducibility; every source-controlled member byte remains exact.
