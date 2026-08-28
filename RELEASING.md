# Release process

Bedrock Guardrail Firewall releases must come from a reviewed, fully tested commit. Publishing a GitHub release is the explicit release authorization. The repository does not use a long-lived PyPI password or API token.

## One-time trusted-publisher setup

Before the first PyPI release:

1. Secure the PyPI maintainer account with two-factor authentication and store its recovery codes outside the repository.
2. Register a pending PyPI trusted publisher for project `bedrock-guardrail-firewall`, GitHub owner `fusiontechstrategies`, repository `Bedrock-Guardrail-Firewall`, workflow `publish.yml`, and environment `pypi`.
3. Create the GitHub `pypi` environment and require maintainer approval before deployment.
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

The `Release candidate` workflow can be started manually with the proposed tag to test its build, evidence, and provenance jobs. A manual run never creates or changes a GitHub release and never publishes to PyPI.

## Publish

1. Merge only after branch protections and every required check pass.
2. Create the immutable `vX.Y.Z` tag from the approved merge commit.
3. Wait for the release-candidate workflow to build and attest the distributions and populate the draft GitHub release.
4. Confirm the draft contains exactly five assets: the wheel, source distribution, SPDX 2.3 dependency SBOM, `SHA256SUMS.txt`, and `release-evidence.json`. Review their provenance and contents along with the release notes.
5. Publish the GitHub release only after explicit release approval.
6. Approve the protected `pypi` environment after the publish workflow has downloaded and reverified the exact public release assets.

The candidate workflow creates GitHub build-provenance attestations and attaches the wheel, source distribution, SPDX 2.3 dependency SBOM, checksums, and evidence to a draft GitHub release. Existing draft assets are accepted only when their bytes match and different bytes are never overwritten. The workflow rejects extra draft assets. Publishing the reviewed draft starts a separate workflow that first requires the same exact five-asset set, recreates and compares the evidence, and then sends those exact downloaded distributions to PyPI through trusted publishing. An existing PyPI version is not skipped silently.

## Post-publication verification

1. Confirm the GitHub workflow and PyPI attestations are successful.
2. Download every GitHub asset and recompute `SHA256SUMS.txt` independently.
3. Create a clean isolated environment and install the exact version from PyPI.
4. Verify distribution metadata, the console version, the offline doctor command, packaged policies, and the sanitized demo.
5. Confirm no unexpected dependency is installed for the standard-library-only core.
6. Link the verified PyPI project from the README and GitHub release.
7. Record the tag, commit, hashes, attestation links, test evidence, and publication time.

If any check fails, stop publication or publish a new version after correction. Never rebuild or replace an already published version.
