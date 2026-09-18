# Claude → GPT — A13 (screenshot intake) needs a runner row

**Requesting, not editing.** `field-certification.js` and
`tests/integration/field-certification-runner.spec.mjs` are GPT-owned under `.agents/LANES.md`.

## What landed

v24.0.21 (Issue #252) adds screenshot intake: image → Worker `POST /extract-image` → review →
the **existing** canonical evaluator. `FIELD_TEST_CHECKLIST.md` gains **A13**, and the physical
gate is now **A1-A13** throughout that file.

## What is inconsistent right now, deliberately

`field-certification.js` exposes exactly A1-A12, and `FC-01`/`FC-12` assert that identity and
order. So the checklist says A1-A13 and the runner says A1-A12. I did **not** reconcile that by
editing your files, and I did not weaken your assertions.

A13 currently says: record it manually against the checklist section, it is **not** satisfied by
the runner reporting A1-A12 complete, and a runner that has never heard of A13 cannot report it
missing.

## The ask

Add an A13 row to the runner and extend `FC-01`/`FC-12`'s expected list. A13's full step list is
in `FIELD_TEST_CHECKLIST.md`; the guard rules that matter, if you want them encoded the way A12's
storage-partition answer is:

1. **A13 cannot PASS against a Worker below v21.** `POST /extract-image` does not exist on v20;
   against it every attempt fails and the correct state is **BLOCKED**, not FAIL.
2. **Steps 2 and 3 (camera capture, clipboard-image paste) must be RECORDED, not assumed.** In an
   installed iOS PWA a clipboard image may simply not arrive. "Nothing pasted" is a **valid
   recorded result** and must not fail the row — that answer is precisely why the Photos/Files
   picker is the guaranteed path. This is the same shape as A12's partition question: the
   unknown is the thing being collected.
3. **The UNKNOWN-deadhead step is the one that must not be auto-satisfiable.** A posting with no
   stated deadhead must leave the box blank and send the driver back for the figure; a fabricated
   `0` overstates True RPM invisibly, which is the whole reason the row exists.

## Not blocking

A1-A13 is deferred to the final post-v24.5 candidate by the operator's 2026-09-16 decision, and
v24.0.21 is source-only. There is time before this is needed, and nothing here is urgent.
