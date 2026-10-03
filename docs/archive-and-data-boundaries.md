# Archive verification and local data startup

The configured data directory stays an absolute lexical path. Link checks do not
authorize a separately resolved target. Startup opens the original namespace one
component at a time, rejects links/reparse points, validates ancestor ownership
and mutation permissions, and retains those handles throughout initialization.
The final data directory is opened or created beneath its verified existing
parent; the privacy key is opened relative to the retained data descriptor.
Injected keys do not skip namespace validation. Missing intermediate parents must
be provisioned by the operator first. No existing permissions are repaired.

On POSIX the final directory must belong to the process user and be private.
Ancestors must belong to that user or root and exclude other-user mutation; a
root-owned sticky temporary parent is supported. Windows accepts the validated
owner plus SYSTEM, Administrators and TrustedInstaller as local trusted
authorities; other principals cannot mutate the namespace or its ACL. These
checks do not exclude a malicious process with the same user identity, a retained
historical ACL-editing capability, or an administrator. Later store operations
reopen the original lexical namespace with their existing guarded file/lock APIs.

The final Windows data directory must have the current user's SID as owner.
New application directories set that owner in their creation descriptor, even
under an elevated token whose default directory owner is Administrators. An
existing Administrators-owned leaf is refused rather than repaired. Offline
fixtures create a fresh private child and retain their original cleanup parent;
installed-package controls request a missing private leaf through public startup.

All distribution entry points share pre-parser archive limits: 64 MiB compressed,
128 MiB raw TAR, 16 MiB per file, 64 MiB total member bodies, 10,000 physical TAR
headers/ZIP members, 4 MiB ZIP central directory, 64 KiB TAR extension metadata,
and ZIP expansion ratio at most 1,000. ZIP supports stored/deflate ordinary
single-volume archives; multipart/global ZIP64, encryption, unsupported methods,
oversized structures and trailing data are refused before `ZipFile` constructs
its member list. Every referenced local header must agree with its central entry
on the filename, flags, method, CRC, sizes and timestamp. Member ranges cover the
whole local-data region without preambles, gaps or overlap; bounded raw deflate
validation checks actual decoded size/CRC and rejects extra streams or padding.
Streaming data descriptors, ZIP64 conventions, extras, entry/archive comments
and explicit directories are unsupported for these pinned canonical wheels.
TAR gzip decoding is chunked to a bounded disk spool, and
physical header limits precede `tarfile` parsing. Logical TAR sizes and names are
checked again after bounded PAX interpretation. Normalization retains metadata
and streaming digests, copies bodies from the spool, and verifies the normalized
archive before replacing its input. Refused inputs remain unchanged.

Privileged release verification treats selected source and artifacts as data.
Every installed wheel member must match authenticated source bytes or metadata
statically reconstructed from the reviewed TOML, README, LICENSE and NOTICE.
The complete METADATA body/headers, WHEEL backend/tag declarations, entry points,
top-level name, declared license files and exact member set are checked; RECORD
must cover and hash that set. The supported deterministic backend conventions are
setuptools 84.0.0 and wheel 0.48.0. Uniform LF/CRLF generated METADATA forms are
explicit platform alternatives; source-controlled bytes are never translated.
Wheel attributes are explicit platform alternatives: Unix regular files `0644`,
Windows-built regular files `0666`, and generated RECORD regular files `0664`.
Each archive uses one Unix or Windows host convention, ZIP creator/extractor
version 2.0, with no
internal/DOS attributes or additional flag bits. Executable, special-file and
other permission/metadata variants are refused. These are ZIP declarations;
verification does not apply them to the host filesystem.
Other metadata encodings or semantically equivalent but noncanonical marker text
require a reviewed convention change. No selected build hook is executed by this
static verification. Candidate builds may execute authenticated source hooks only
inside the existing unprivileged candidate workflow.

The separate no-bypass version-tag creation guard remains a release prerequisite:
new `v*` tags are blocked until a separately reviewed trusted creation mechanism
is enabled. Main-only owner-review environments and immutable tag controls remain
required. Administrators able to change those policies remain trusted authorities.

## Provenance API admission

The validate_wheel and validate_sdist APIs require an explicit reviewed source
directory. An omitted source directory fails before opening the artifact.
Structural archive checks alone do not constitute provenance. The privileged
pipelines already pass authenticated source and retain the same artifact snapshots
throughout validation. This API restriction does not add a publication path or
change release approval.

## Shared-state consistency and capacity

Audit verification holds the same writer lock while reading the event stream,
chain head and comparing an independently supplied trusted checkpoint. Without
a trusted checkpoint, a coherent valid stream still reports
trusted_checkpoint_required; it does not become an authenticated external proof.
The canonical empty checkpoint is count zero with no last hash. Contradictory
hash/count inputs are refused. Missing or explicit empty events with a missing
or explicitly null head use the same checkpoint matcher; a nonempty or malformed
head still refuses a missing stream. A zero checkpoint cannot match a nonempty
valid stream.

Behavior state uses the same 16 MiB encoded-byte limit for reads and writes.
Writes use compact ASCII JSON with a final newline. Existing readable JSON remains
supported. Age and configured subject-count pruning still apply; if encoded bytes
exceed capacity, oldest subjects are removed deterministically before writing.
Byte accounting includes escaped Unicode, keys, punctuation and envelope metadata.
An oversized envelope or write is refused while preserving the prior file.

Before each live Bedrock content evaluation, current local detections must permit
external evaluation. Transformed input is rechecked locally before any output
call. REVIEW, ESCALATE and BLOCK prevent that subsequent content call. Stub mode,
explicit disabled mode and content-free audit/review telemetry retain their own
existing behavior.
