import { createSuite, ok, eq } from '../lib/harness.mjs';
import { parseLanes, checkLocks, checkHistoricalLock } from '../../scripts/lane-guard.mjs';
const {test,run}=createSuite('unit/audit-lock-session.spec.mjs');
const rows=parseLanes('| `app.js` | SHARED | serialized |\n| `scripts/` | gpt | own |');
const rec={name:'app-js.lock',owner:'gpt',token:'session-A',paths:['app.js'],started_utc:'2026-10-02T07:53:48Z',expected_release_utc:'2026-10-02T15:53:48Z'};
const at=Date.parse('2026-10-02T08:30:00Z');
test('[LOCK-AUDIT-01] matching lane and session pass',()=>eq(checkLocks(rows,'gpt',['app.js'],[rec],at,'session-A').length,0));
test('[LOCK-AUDIT-02] same lane cannot use another session claim',()=>eq(checkLocks(rows,'gpt',['app.js'],[rec],at,'session-B')[0].kind,'other-session'));
test('[LOCK-AUDIT-03] missing session token is a violation',()=>eq(checkLocks(rows,'gpt',['app.js'],[rec],at)[0].kind,'missing-lock-token'));
test('[LOCK-AUDIT-04] historical authority requires owner, token and all covered paths',()=>{
 ok(checkHistoricalLock(rec,'gpt',['app.js'],at,'session-A'));
 ok(!checkHistoricalLock(rec,'claude',['app.js'],at,'session-A'));
 ok(!checkHistoricalLock(rec,'gpt',['app.js'],at,'session-B'));
 ok(!checkHistoricalLock(rec,'gpt',['index.html'],at,'session-A'));
});
test('[LOCK-AUDIT-05] future and expired historical claims cannot authorize',()=>{
 ok(!checkHistoricalLock(rec,'gpt',['app.js'],Date.parse('2026-10-02T06:00:00Z'),'session-A'));
 ok(!checkHistoricalLock(rec,'gpt',['app.js'],Date.parse('2026-10-03T08:30:00Z'),'session-A'));
});
export const runSpec=run;
