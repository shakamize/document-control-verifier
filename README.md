# Document control trail verifier

`verify-trail.mjs` recomputes the hashes in an export of a Confluence document
control audit trail and tells you whether they still agree with the rows they
were computed over.

**It exists because you should not have to take the vendor's word for it.** The
app that keeps the record is written by the same people who publish it, so a
button inside the app saying "verified" would be that vendor vouching for
itself. This runs on your machine, against a file you hold, from source you can
read before you run it.

## Running it

Node 18 or later, and nothing else. There is nothing to install.

```
node verify-trail.mjs my-export.json
```

Keep every export you take. Once you hold more than one, pass them all, oldest
first, and each earlier file is also checked against the later ones:

```
node verify-trail.mjs 2026-06-01.json 2026-09-01.json 2026-12-01.json
```

It exits `0` when every chain it read recomputes, `1` when something is broken,
and `2` when it could not tell.

## Checking that you have the file we published

Every release names the SHA-256 of the `verify-trail.mjs` it ships. The digest
is computed by the release job from the bytes it attaches, so it is not a value
anybody typed. Compare it against your copy:

```
shasum -a 256 verify-trail.mjs
```

On Windows:

```
certutil -hashfile verify-trail.mjs SHA256
```

Take the digest from the release page for the version you downloaded rather than
from a link that follows the newest release, so that the file and the digest you
compare it against are frozen together.

## Checking the verifier before you trust it with your own record

`fixtures/` holds exports whose contents are known, one per export format the
verifier reads. Run it against each of them first, one file at a time, and each
should report every chain verifying and exit `0`. Then alter one character
inside any row in a copy of one, run it again, and it should report that
document broken at the sequence number you touched. A checker that cannot be
made to fail is not telling you anything.

Pass the fixtures one at a time rather than all together. Several files given at
once are read as successive takes of the same trail, oldest first, and these are
not that.

## What the answers mean

- **verified**, with a row count and a head hash per document. Every row hashes
  to the value stored with it, every row follows the one before it, and the
  sequence numbers run without a gap.
- **BROKEN**, naming the document and the sequence number. A row was altered, or
  a row was removed from the middle of a chain, or a row does not follow the one
  before it. The sequence number is where the chain stops agreeing with itself,
  which is at or before the change.
- **Cannot tell**. The file could not be read, or it is in a format or a hash
  construction this verifier does not implement. This is not a report that the
  record is intact, and it is not a report that it is broken.
- **identity erased**. Somebody exercised their right to have their personal
  data erased, and the app erased the account behind that approver key. The
  approval still stands, the row is untouched, and the chain still verifies.
  This is a lawful erasure and not a defect in the record.

An export never contains an Atlassian account identifier. Rows carry a
pseudonymous approver key, and the mapping from that key to an account stays
inside the app so that an erasure request can be honoured without rewriting a
single hashed row. What an export carries is the standing of each key: whether
the app still holds an account for it, whether it was erased, or whether it
could not be looked up.

## The limit, stated plainly

A hash chain detects any altered row and any row removed from the middle. **It
cannot, on its own, detect rows removed from the end**, because nothing inside a
chain records how long the chain should be. A trail whose last three rows were
deleted verifies perfectly as a shorter trail.

Detecting that needs an anchor the vendor cannot reach, which is an export you
already hold. That is why this command takes several files, and why keeping
every export is worth the trouble: comparing an earlier one against a later one
is what turns "the rows present agree with each other" into "nothing that was
here before has gone".

## Writing your own instead

Every export describes its own hash construction under `construction`, which is
enough to check the record without this program at all:

- the digest is `sha256`, rendered as lower case hex
- ten parts are hashed in the order `construction.fields` lists: the literal
  algorithm identifier, then nine fields from the row
- each part is prefixed with its length in UTF-8 bytes and a colon
- the parts are joined with `|`
- the first row of every document chains from `construction.genesisHash`, which
  is sixty four zeros

`verify-trail.mjs` refuses to answer if an export describes a construction other
than the one it implements, rather than checking it against the wrong rule.

## Versions and compatibility

Each release is a version of the verifier, and a released version never stops
reading an export format the app has already shipped. The line it prints when it
runs names the version and the formats it reads, so an output you keep alongside
an export records what produced it.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.

## Reporting a problem

Open an issue on this repository. If you believe the verifier reports a record
as intact when it is not, say so in the issue title, and include the export and
the output rather than a description of them.
