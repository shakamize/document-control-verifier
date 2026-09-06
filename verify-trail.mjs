// SPDX-License-Identifier: Apache-2.0
// Copyright Shakamize
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { argv, exit, stdout } from 'node:process';

const VERSION = '1.0.0';

const ALGORITHM = 'dc-audit-sha256-v1';

const KNOWN_FORMATS = ['dc-audit-export-v1', 'dc-audit-export-v2'];

const GENESIS_HASH = '0'.repeat(64);

const CHAINED_FIELDS = [
  'algorithm',
  'previousHash',
  'documentId',
  'sequenceNumber',
  'spaceKey',
  'recordedAt',
  'eventType',
  'actorKey',
  'outcome',
  'detailCanonical',
];

const SEPARATOR = '|';

const VERIFIED = 0;

const BROKEN = 1;

const CANNOT_TELL = 2;

const partOf = (row, field) => {
  if (field === 'algorithm') {
    return ALGORITHM;
  }
  if (field === 'sequenceNumber') {
    return String(row.sequenceNumber);
  }
  return row[field];
};

const frame = (part) => `${Buffer.byteLength(part, 'utf8')}:${part}`;

const hashOf = (row) =>
  createHash('sha256')
    .update(
      CHAINED_FIELDS.map((field) => partOf(row, field))
        .map(frame)
        .join(SEPARATOR),
      'utf8',
    )
    .digest('hex');

const isText = (value) => typeof value === 'string' && value.length > 0;

const rowIsReadable = (row) =>
  row !== null &&
  typeof row === 'object' &&
  Number.isSafeInteger(row.sequenceNumber) &&
  CHAINED_FIELDS.filter((field) => field !== 'algorithm' && field !== 'sequenceNumber').every(
    (field) => isText(row[field]),
  ) &&
  isText(row.hash) &&
  typeof row.detailCanonical === 'string';

const chainedRowsOf = (document) =>
  Array.isArray(document.rows) ? document.rows.map((row) => (row ?? {}).chained ?? {}) : null;

const verifyDocument = (document) => {
  const rows = chainedRowsOf(document);
  if (rows === null || !rows.every(rowIsReadable)) {
    return {
      status: 'unreadable',
      reason: 'a row in this document is not shaped like a trail row',
    };
  }
  if (rows.length === 0) {
    return { status: 'empty' };
  }

  let previousHash = GENESIS_HASH;
  let expected = 1;

  for (const row of rows) {
    if (row.documentId !== rows[0].documentId) {
      return {
        status: 'broken',
        sequenceNumber: row.sequenceNumber,
        reason: 'a row belongs to another document',
      };
    }
    if (row.sequenceNumber !== expected) {
      return {
        status: 'broken',
        sequenceNumber: expected,
        reason: 'a row is missing or out of order',
      };
    }
    if (row.previousHash !== previousHash) {
      return {
        status: 'broken',
        sequenceNumber: row.sequenceNumber,
        reason: 'a row does not follow the one before it',
      };
    }
    if (hashOf(row) !== row.hash) {
      return {
        status: 'broken',
        sequenceNumber: row.sequenceNumber,
        reason: 'a row does not match its own hash',
      };
    }
    previousHash = row.hash;
    expected += 1;
  }

  return { status: 'verified', rows: rows.length, headHash: previousHash };
};

const constructionMatches = (construction) => {
  if (construction === undefined) {
    return true;
  }
  return (
    construction !== null &&
    typeof construction === 'object' &&
    construction.algorithm === ALGORITHM &&
    construction.digest === 'sha256' &&
    construction.encoding === 'hex' &&
    construction.genesisHash === GENESIS_HASH &&
    construction.separator === SEPARATOR &&
    Array.isArray(construction.fields) &&
    construction.fields.length === CHAINED_FIELDS.length &&
    construction.fields.every((field, index) => field === CHAINED_FIELDS[index])
  );
};

const attributionOf = (envelope) => {
  const carried = envelope.attribution;
  if (carried === undefined || carried === null || carried.status !== 'carried') {
    return null;
  }
  return Array.isArray(carried.approvers) ? carried.approvers : null;
};

const approverKeysIn = (envelope) => {
  const keys = new Set();
  for (const document of envelope.documents) {
    for (const row of document.rows ?? []) {
      const key = (row ?? {}).chained?.actorKey;
      if (isText(key)) {
        keys.add(key);
      }
    }
  }
  return [...keys].sort();
};

const readEnvelope = (path) => {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    return { status: 'unreadable', reason: `this file could not be read: ${error.message}` };
  }

  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch (error) {
    return { status: 'unreadable', reason: `this file is not readable JSON: ${error.message}` };
  }

  if (envelope === null || typeof envelope !== 'object' || !Array.isArray(envelope.documents)) {
    return {
      status: 'unreadable',
      reason: 'this file is not an export of a document control trail',
    };
  }
  if (!KNOWN_FORMATS.includes(envelope.format)) {
    return {
      status: 'unreadable',
      reason: `this verifier does not know the export format ${String(envelope.format)}`,
    };
  }
  if (envelope.algorithm !== ALGORITHM) {
    return {
      status: 'unreadable',
      reason: `this verifier does not implement the hash ${String(envelope.algorithm)}`,
    };
  }
  if (!constructionMatches(envelope.construction)) {
    return {
      status: 'unreadable',
      reason: 'this export describes a hash construction this verifier does not implement',
    };
  }

  return { status: 'read', envelope };
};

const say = (line) => stdout.write(`${line}\n`);

const reportAttribution = (envelope) => {
  const approvers = attributionOf(envelope);
  const keys = approverKeysIn(envelope);

  if (approvers === null) {
    say(
      '  Attribution: this export carries none, so who signed these approvals cannot be told from it.',
    );
    say('  That is not a report that the approvals are unsigned.');
    return 0;
  }

  const standingOf = new Map(approvers.map((approver) => [approver.approverKey, approver]));
  const erased = [];

  for (const key of keys) {
    const approver = standingOf.get(key);
    if (approver === undefined) {
      say(
        `  ${key}: no standing in this export, so its attribution cannot be told from this file.`,
      );
    } else if (approver.identity === 'erased') {
      erased.push(key);
      say(
        `  ${key}: identity erased at the person's request${approver.erasedAt ? ` on ${approver.erasedAt}` : ''}. The approval stands and the chain is unaffected.`,
      );
    } else if (approver.identity === 'known') {
      say(
        `  ${key}: the app holds the account behind this key. Account identifiers are never written into an export.`,
      );
    } else if (approver.identity === 'system') {
      say(`  ${key}: the app itself, not a person.`);
    } else if (approver.identity === 'unknown') {
      say(
        `  ${key}: the app holds no account for this key. That is not a report that nobody signed.`,
      );
    } else {
      say(
        `  ${key}: the app could not look this key up${approver.error ? `: ${approver.error}` : ''}. That is not a report that nobody signed.`,
      );
    }
  }

  return erased.length;
};

const rowsByDocument = (envelope) => {
  const byDocument = new Map();
  for (const document of envelope.documents) {
    byDocument.set(
      document.documentId,
      (document.rows ?? []).map((row) => (row ?? {}).chained ?? {}),
    );
  }
  return byDocument;
};

const compareTakes = (earlier, later) => {
  const before = rowsByDocument(earlier.envelope);
  const after = rowsByDocument(later.envelope);
  const receded = [];

  for (const [documentId, rows] of before) {
    const now = after.get(documentId);
    if (now === undefined) {
      receded.push(`${documentId}: present in ${earlier.path} and absent from ${later.path}`);
      continue;
    }
    if (now.length < rows.length) {
      receded.push(
        `${documentId}: ${rows.length} rows in ${earlier.path} and ${now.length} in ${later.path}`,
      );
      continue;
    }
    for (const [index, row] of rows.entries()) {
      if (now[index]?.hash !== row.hash) {
        receded.push(
          `${documentId}: row ${String(row.sequenceNumber)} is not the row ${earlier.path} held`,
        );
        break;
      }
    }
  }

  return receded;
};

const verifyFile = (path) => {
  say(`${path}`);
  const reading = readEnvelope(path);
  if (reading.status === 'unreadable') {
    say(`  Cannot tell: ${reading.reason}`);
    say('  This is not a report that the record is intact.');
    return { path, verdict: CANNOT_TELL };
  }

  const envelope = reading.envelope;
  let verdict = VERIFIED;
  let unreadable = 0;
  let broken = 0;
  let verified = 0;

  for (const document of envelope.documents) {
    const result = verifyDocument(document);
    if (result.status === 'broken') {
      broken += 1;
      say(
        `  BROKEN ${document.documentId} at sequence ${String(result.sequenceNumber)}: ${result.reason}`,
      );
    } else if (result.status === 'unreadable') {
      unreadable += 1;
      say(`  CANNOT TELL ${document.documentId}: ${result.reason}`);
    } else if (result.status === 'empty') {
      say(`  ${document.documentId}: no rows in this export.`);
    } else {
      verified += 1;
      say(
        `  verified ${document.documentId}: ${String(result.rows)} rows, head hash ${result.headHash}`,
      );
    }
  }

  if (broken > 0) {
    verdict = BROKEN;
  } else if (unreadable > 0) {
    verdict = CANNOT_TELL;
  }

  say(
    `  Taken ${String(envelope.exportedAt)}: ${String(verified)} verified, ${String(broken)} broken, ${String(unreadable)} that cannot be told.`,
  );
  const erased = reportAttribution(envelope);
  if (erased > 0) {
    say(
      `  ${String(erased)} approver identity erased at the person's request. That is a lawful erasure, not a broken record.`,
    );
  }

  return { path, verdict, reading };
};

const banner = () => `verify-trail ${VERSION}, which reads ${KNOWN_FORMATS.join(' and ')}.`;

const usage = () => {
  say(banner());
  say('');
  say('Check a document control trail export against the hashes inside it.');
  say('');
  say('  node verify-trail.mjs <export.json> [an-earlier-export.json ...]');
  say('');
  say('Give more than one file, oldest first, and every earlier file is also checked');
  say('against the later ones for rows that have gone missing from the end.');
};

const main = () => {
  const paths = argv.slice(2).filter((argument) => !argument.startsWith('-'));
  if (paths.length === 0) {
    usage();
    return CANNOT_TELL;
  }

  say(banner());
  say('');
  const results = paths.map(verifyFile);
  let verdict = results.reduce((worst, result) => Math.max(worst, result.verdict), VERIFIED);

  const readable = results.filter((result) => result.reading !== undefined);
  for (let index = 1; index < readable.length; index += 1) {
    const earlier = {
      path: readable[index - 1].path,
      envelope: readable[index - 1].reading.envelope,
    };
    const later = { path: readable[index].path, envelope: readable[index].reading.envelope };
    const receded = compareTakes(earlier, later);
    say('');
    if (receded.length === 0) {
      say(`${earlier.path} is held in full by ${later.path}.`);
    } else {
      verdict = Math.max(verdict, BROKEN);
      say(`BROKEN: ${later.path} no longer holds what ${earlier.path} did.`);
      for (const line of receded) {
        say(`  ${line}`);
      }
    }
  }

  say('');
  say('What this check can and cannot show. It recomputes every hash and detects any');
  say('altered row and any row removed from the middle of a chain. On a single file it');
  say('cannot detect rows removed from the end of a chain, because nothing inside a chain');
  say('records how long it should be. Detecting that needs an export you already hold,');
  say('which is why keeping every export and passing them all to this command matters.');

  if (verdict === VERIFIED) {
    say('');
    say('Every chain checked recomputes to the hashes it carries.');
  }
  return verdict;
};

exit(main());
