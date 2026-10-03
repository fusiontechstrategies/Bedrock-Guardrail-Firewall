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
