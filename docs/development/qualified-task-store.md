# Qualified task observations

The qualified store keeps source identity with task history. A task label alone
does not identify a task across sources. Each stored reference carries the
complete canonical TaskRef, its digest, and all ten indexed fields. Readers
decode the canonical bytes and compare every index before consuming a record.

The logical record families are sources, projections, dependency edges, events,
message bindings, assignments, acceptances, source-write intents and scheduler
admissions. Physical observation IDs are separate from their logical keys.
Changing a task's current reference or an assignment's phase creates a new
observation; it does not rewrite the signed original binding.

Replicated records remain observations. They cannot enroll a source, commit a
canonical status, elect a writer, acquire a lease, revive a reservation or start
a worker. Source-write and scheduler journal tables are nonreplicated mirrors.
The existing original host journals retain authority. Before calling a
projection current, the CLI checks the enrolled source, exact canonical file,
complete reference and original writer journal. Neither a cached status nor
the largest timestamp or database revision substitutes for those checks.

## Complete records and conflicts

A complete storage envelope is bounded to 256 KiB. It is stored in at most four
64 KiB parts so that the native per-value bound does not truncate an otherwise
valid 128 KiB signed task frame. The signed binary frame is preserved in its
immutable binding; phase data remains separate. This storage framing does not
change the task signature transcript.

Headers, parts and derived reference indexes enter one native transaction.
Readers require exact contiguous ordinals, part lengths, total length, digest
and canonical decoding. A missing, extra or corrupt part exposes no complete
record. Batch and native image bounds apply independently.

An observation's physical variant key includes its complete record digest.
Different variants under the same observation identity remain available for
quarantine rather than overwriting each other through last-writer-wins.
Immutable message, transition, assignment and acceptance identities also bind
their full context. A conflicting original binding preserves the accepted
original and incoming evidence. Exact replay adds no duplicate. A legitimate
later phase may append while retaining the same original binding.

Missing dependencies remain held observations. Later arrivals can make a
relationship resolvable within a snapshot, but cannot supply authentication,
current enrollment or execution permission. Local journal mirrors cannot enter
a replica-observation batch.
The API accepts typed, bounded batches; CRR registration does not expose an
arbitrary raw replica-change import endpoint.

## Migration and legacy history

V2 has a fixed schema and a separate typed reader and writer. V1's header and
schema checks remain strict. Selecting a V2 reader is explicit; a filename or
caller-provided version number does not select a migration or grant authority.

Migration uses one original retained write owner. It verifies the V1 preimage,
changes the isolated native image in one transaction, preserves the site and
legacy content, checks the exact V2 schema, and checked-closes native ownership
before the existing staging, intent, rename and fsync path. Schema version,
source revision and CRSQL database version are distinct counters.

Interrupted operations retain their original artifacts. A refused reopen is a
held outcome, not evidence of successful recovery. No caller may clear markers,
repeat migration under a new operation ID, or adopt a replacement inode merely
to make a retry succeed.

Historical messages and their signed bytes stay unchanged and
`LegacyUnqualified`. A separately recorded association may identify a source
only from the authorized exact repository/path/case/generation/revision/preimage
pin. It remains inferred: the historical sender did not sign that association.
Ambiguous historical IDs remain unqualified.

These APIs do not perform a live fleet cutover, fence old daemons, expose raw
SQL or native connections, or supply missing production authentication, host
time or custody profiles. Workbench presentation belongs to P0-11; source moves
and retirement recovery belong to P0-12. A schema migration alone grants none
of those capabilities.
