#!/usr/bin/env node
// lane-guard — makes /.agents/LANES.md ownership and the /AGENTS.md lock
// protocol mechanically checkable instead of markdown an agent must remember
// to read.
//
// Zero dependencies, no build step — same constraints as the rest of the repo.
//
// Authority boundary: this script ENFORCES AGENTS.md/LANES.md. It never edits
// them, never deletes a lock, and never steals one. A lock past its TTL is
// REPORTED as stale; reaping stays a deliberate act per AGENTS.md (delete,
// commit, push, log the token + reason in STATUS.md).
//
// Two hard rules encoded here:
//   1. Unknown path => FAIL. A path with no LANES.md row cannot be classified,
//      so it is never quietly allowed.
//   2. Stale lock => FAIL for everyone, including its own holder. A stale lock
//      grants nothing and blocks nothing silently; it must be reaped in the open.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

export const COORD_REF = 'origin/agent-coordination';
export const LOCK_DIR = '.agents/locks';

// AGENTS.md: "Reap: past expected_release_utc + 2h either agent may delete".
export const REAP_GRACE_MS = 2 * 60 * 60 * 1000;

// D1 (operator-approved 2026-08-26). AGENTS.md declares `agent/claude/<task>`
// and `agent/gpt/<task>`. Reality on origin: 0 of 108 branches use
// `agent/claude/*`, while the Claude harness assigns `claude/*` (50 branches)
// and earlier GPT rounds used `chatgpt/*` (7). A check written against the
// declared names alone would reject the branch the harness hands out, so the
// namespaces actually in use are blessed as aliases.
export const NAMESPACES = [
  { re: /^agent\/claude\//, agent: 'claude' },
  { re: /^claude\//,        agent: 'claude' },
  { re: /^agent\/gpt\//,    agent: 'gpt'    },
  { re: /^chatgpt\//,       agent: 'gpt'    }
];

export const AGENTS = ['claude', 'gpt'];

/* ---------------------------------------------------------------- ownership */

// LANES.md is the single source of truth. We parse its table rather than
// generating a second machine-readable copy, because two copies is exactly the
// drift class this whole change exists to remove.
export function parseLanes(md){
  const rows = [];
  for (const line of md.split('\n')){
    const m = line.match(/^\|\s*`([^`]+)`\s*\|\s*([A-Za-z]+)\s*\|/);
    if (!m) continue;
    const owner = m[2].toLowerCase();
    if (owner !== 'claude' && owner !== 'gpt' && owner !== 'shared') continue;
    rows.push({ path: m[1], owner });
  }
  return rows;
}

// Longest-prefix match. A row ending in `/` owns its whole subtree; any other
// row must match exactly. Returns null for an unclassifiable path (fail closed).
export function ownerForPath(rows, file){
  let best = null;
  for (const r of rows){
    const hit = r.path.endsWith('/') ? file.startsWith(r.path) : file === r.path;
    if (!hit) continue;
    if (!best || r.path.length > best.path.length) best = r;
  }
  return best ? best.owner : null;
}

export function checkOwnership(rows, agent, files){
  const out = [];
  for (const file of files){
    const owner = ownerForPath(rows, file);
    if (owner === null){
      out.push({ file, kind: 'unowned',
        message: `${file} matches no row in .agents/LANES.md. Ownership cannot be determined, so this fails closed — add a row for it.` });
    } else if (owner !== 'shared' && owner !== agent){
      out.push({ file, kind: 'foreign-lane',
        message: `${file} is ${owner}-owned but the committing agent is ${agent}. Write a request under /.agents/inbox/ on agent-coordination instead of editing it.` });
    }
  }
  return out;
}

/* -------------------------------------------------------------------- locks */

// Accepts the 5-field record already in use on agent-coordination plus the new
// optional `paths:` field. A record without `paths:` parses fine and simply
// covers nothing — see checkLocks.
export function parseLock(text, name){
  const rec = { name, owner:'', token:'', started_utc:'', expected_release_utc:'', paths:[], task:'' };
  for (const line of text.split('\n')){
    const m = line.match(/^([a-z_]+):\s*(.*)$/);
    if (!m) continue;
    const [, key, val] = m;
    if (key === 'paths') rec.paths = val.split(',').map(s => s.trim()).filter(Boolean);
    else if (key in rec) rec[key] = val.trim();
  }
  return rec;
}

// Stale strictly AFTER expected_release_utc + 2h, matching AGENTS.md's "past".
// An unparseable expiry is treated as stale: a record we cannot date is not a
// grant we can honour.
export function lockIsStale(rec, nowMs){
  const t = Date.parse(rec.expected_release_utc);
  if (!Number.isFinite(t)) return true;
  return nowMs > t + REAP_GRACE_MS;
}

export function lockCovers(rec, file){
  return rec.paths.some(p => p.endsWith('/') ? file.startsWith(p) : file === p);
}

// Only SHARED paths need a lock. Claude-owned and gpt-owned paths are settled
// by checkOwnership alone.
export function checkLocks(rows, agent, files, locks, nowMs){
  const out = [];
  const undeclared = locks.filter(l => l.paths.length === 0);
  for (const file of files){
    if (ownerForPath(rows, file) !== 'shared') continue;

    const covering = locks.filter(l => lockCovers(l, file));

    if (covering.length === 0){
      let message = `${file} is SHARED and needs a held lock declaring it. Claim one per /AGENTS.md with a \`paths:\` line covering it.`;
      if (undeclared.length){
        message += ` (${undeclared.length} lock(s) exist but declare no paths: ${undeclared.map(l => l.name).join(', ')} — legacy records cover nothing.)`;
      }
      out.push({ file, kind: 'no-lock', message });
      continue;
    }

    if (covering.some(l => l.owner === agent && !lockIsStale(l, nowMs))) continue; // covered

    const other = covering.find(l => l.owner !== agent && !lockIsStale(l, nowMs));
    if (other){
      out.push({ file, kind: 'held-by-other',
        message: `${file} is locked by ${other.owner} (${LOCK_DIR}/${other.name}, token ${other.token}, expected release ${other.expected_release_utc}). Do other work or use the inbox.` });
      continue;
    }

    const s = covering[0];
    out.push({ file, kind: 'stale-lock',
      message: `${file} is covered only by a STALE lock: ${LOCK_DIR}/${s.name} (owner ${s.owner}, token ${s.token}, expected release ${s.expected_release_utc}). Locks are never auto-stolen. Reap it deliberately per AGENTS.md — delete the file, commit, push, log the token and reason in STATUS.md — then claim your own.` });
  }
  return out;
}

/* --------------------------------------------------------- branch / prefix */

export function namespaceAgent(branch){
  for (const n of NAMESPACES) if (n.re.test(branch)) return n.agent;
  return null;
}

// `commits` is [{ sha, subject, parents }]. Merge commits are exempt: their
// subject is generated by the forge, not by an agent.
export function checkPrefix(branch, commits){
  const agent = namespaceAgent(branch);
  if (agent === null){
    return [{ kind: 'unknown-namespace',
      message: `Branch "${branch}" is in no namespace declared by /AGENTS.md (agent/claude/*, claude/*, agent/gpt/*, chatgpt/*). Declare the namespace in AGENTS.md or rename the branch.` }];
  }
  const want = `[${agent}]`;
  const out = [];
  for (const c of commits){
    if (c.parents > 1) continue;
    if (!c.subject.startsWith(want)){
      out.push({ kind: 'bad-prefix',
        message: `${c.sha.slice(0,8)} "${c.subject}" must start with ${want} on branch namespace "${branch}".` });
    }
  }
  return out;
}

/* ------------------------------------------------------------- git helpers */

function git(args){ return execFileSync('git', args, { encoding: 'utf8' }); }

export function loadLanes(){ return parseLanes(readFileSync('.agents/LANES.md', 'utf8')); }

// Locks live on agent-coordination, which is deliberately NOT checked out here:
// AGENTS.md forbids switching the application worktree to reach coordination
// state. Read them as blobs instead.
export function loadLocks(ref = COORD_REF){
  let listing;
  try { listing = git(['ls-tree', '--name-only', `${ref}:${LOCK_DIR}`]); }
  catch {
    return { ok: false, locks: [],
      error: `cannot read ${ref}:${LOCK_DIR} — run: git fetch origin agent-coordination` };
  }
  const locks = [];
  for (const name of listing.split('\n').map(s => s.trim()).filter(n => n.endsWith('.lock'))){
    try { locks.push(parseLock(git(['show', `${ref}:${LOCK_DIR}/${name}`]), name)); } catch { /* unreadable blob */ }
  }
  return { ok: true, locks };
}

export function commitsInRange(base, head){
  const raw = git(['log', '--format=%H%x1f%P%x1f%s', `${base}..${head}`]).trim();
  if (!raw) return [];
  return raw.split('\n').map(line => {
    const [sha, parents, subject] = line.split('\x1f');
    return { sha, parents: parents.trim().split(/\s+/).filter(Boolean).length, subject };
  });
}

function arg(flag, fallback = ''){
  const i = process.argv.indexOf(flag);
  return i > -1 && process.argv[i+1] ? process.argv[i+1] : fallback;
}

function report(title, violations){
  if (!violations.length){ console.log(`lane-guard: ${title} OK`); return 0; }
  console.error(`\nlane-guard: ${title} FAILED\n`);
  for (const v of violations) console.error(`  [${v.kind}] ${v.message}`);
  console.error('');
  return 1;
}

/* ---------------------------------------------------------------------- CLI */

function main(){
  const cmd = process.argv[2];

  if (cmd === 'precommit'){
    let agent = '';
    try { agent = git(['config', 'freightlogic.agent']).trim(); } catch { /* unset */ }
    if (!AGENTS.includes(agent)){
      console.error(`\nlane-guard: agent identity not set.\n  Run: git config freightlogic.agent claude   (or gpt)\n`);
      return 1;
    }
    const files = git(['diff', '--cached', '--name-only']).split('\n').map(s => s.trim()).filter(Boolean);
    if (!files.length){ console.log('lane-guard: nothing staged'); return 0; }

    const rows = loadLanes();
    let rc = report(`path ownership (${agent}, ${files.length} staged)`, checkOwnership(rows, agent, files));

    const shared = files.filter(f => ownerForPath(rows, f) === 'shared');
    if (shared.length){
      const { ok, locks, error } = loadLocks();
      if (!ok){ console.error(`\nlane-guard: lock check FAILED\n\n  [no-coordination-ref] ${error}\n`); rc = 1; }
      else rc = report('lock coverage', checkLocks(rows, agent, files, locks, Date.now())) || rc;
    }
    return rc;
  }

  if (cmd === 'ci-paths'){
    const branch = arg('--branch');
    const agent = namespaceAgent(branch);
    if (agent === null) return report('branch namespace', checkPrefix(branch, []));
    const files = git(['diff', '--name-only', `${arg('--base')}...${arg('--head')}`])
      .split('\n').map(s => s.trim()).filter(Boolean);
    if (!files.length){ console.log('lane-guard: no changed paths'); return 0; }
    return report(`path ownership (${agent}, ${files.length} changed)`, checkOwnership(loadLanes(), agent, files));
  }

  if (cmd === 'ci-prefix'){
    const branch = arg('--branch');
    return report(`commit prefix (${branch})`, checkPrefix(branch, commitsInRange(arg('--base'), arg('--head'))));
  }

  if (cmd === 'status'){
    const { ok, locks, error } = loadLocks();
    if (!ok){ console.error(`lane-guard: ${error}`); return 1; }
    if (!locks.length){ console.log('lane-guard: no locks held'); return 0; }
    const now = Date.now();
    for (const l of locks){
      const stale = lockIsStale(l, now);
      console.log(`${stale ? 'STALE ' : 'HELD  '} ${l.name}  owner=${l.owner}  token=${l.token}  expires=${l.expected_release_utc}`);
      console.log(`        paths: ${l.paths.length ? l.paths.join(', ') : '(none declared — covers nothing)'}`);
      if (stale) console.log('        reap deliberately per AGENTS.md; never auto-stolen');
    }
    return 0; // reporting only
  }

  if (cmd === 'trailer'){
    // Emitted by .githooks/prepare-commit-msg. Prints nothing (and never fails
    // the commit) unless a SHARED path is staged and a lock of ours covers it.
    let agent = '';
    try { agent = git(['config', 'freightlogic.agent']).trim(); } catch { return 0; }
    if (!AGENTS.includes(agent)) return 0;
    const files = git(['diff', '--cached', '--name-only']).split('\n').map(s => s.trim()).filter(Boolean);
    const rows = loadLanes();
    const shared = files.filter(f => ownerForPath(rows, f) === 'shared');
    if (!shared.length) return 0;
    const { ok, locks } = loadLocks();
    if (!ok) return 0;
    const now = Date.now();
    const used = new Set();
    for (const f of shared){
      const l = locks.find(l => l.owner === agent && !lockIsStale(l, now) && lockCovers(l, f));
      if (l) used.add(`${l.name.replace(/\.lock$/, '')}/${l.token}`);
    }
    for (const u of used) console.log(`\nFL-Lock: ${u}`);
    return 0;
  }

  if (cmd === 'ci-trailer'){
    // WARN-ONLY for its first round (see .github/workflows/lanes.yml): always
    // exits 0. It reports commits that changed a SHARED path without naming the
    // lock that authorised them, and trailers whose token is absent from
    // agent-coordination history.
    const rows = loadLanes();
    let flagged = 0;
    for (const c of commitsInRange(arg('--base'), arg('--head'))){
      if (c.parents > 1) continue;
      const files = git(['show', '--name-only', '--format=', c.sha]).split('\n').map(s => s.trim()).filter(Boolean);
      if (!files.some(f => ownerForPath(rows, f) === 'shared')) continue;
      const body = git(['log', '-1', '--format=%B', c.sha]);
      const m = body.match(/^FL-Lock:\s*(\S+)\/(\S+)\s*$/m);
      if (!m){
        console.log(`  WARN ${c.sha.slice(0,8)} changed a SHARED path with no FL-Lock trailer — "${c.subject}"`);
        flagged++;
        continue;
      }
      let seen = '';
      try { seen = git(['log', '--format=%H', `-S${m[2]}`, COORD_REF, '--', `${LOCK_DIR}/${m[1]}.lock`]).trim(); } catch { /* ref missing */ }
      if (!seen){
        console.log(`  WARN ${c.sha.slice(0,8)} names lock ${m[1]} token ${m[2]}, not found in ${COORD_REF} history`);
        flagged++;
      }
    }
    console.log(flagged ? `lane-guard: lock trailer audit — ${flagged} warning(s) (warn-only)` : 'lane-guard: lock trailer audit OK');
    return 0;
  }

  console.error('usage: lane-guard.mjs <precommit|trailer|ci-paths|ci-prefix|ci-trailer|status> [--branch B --base A --head B]');
  return 2;
}

// Only run the CLI when invoked directly, so the spec can import the pure parts.
if (process.argv[1] && process.argv[1].endsWith('lane-guard.mjs')) process.exit(main());
