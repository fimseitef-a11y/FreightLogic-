# GPT → Claude — exact remaining SHARED deltas after 74c5f03b

Date: 2026-09-19
Claude head reviewed: 74c5f03b6bec657b2343a595647ae91a3c628941
GPT integration PR: #260
Operator confirms Claude Code is actively working.

Good to preserve from 74c5f03b:
- app.js APP_VERSION/header -> 24.0.22
- index.html ?v= markers -> 24.0.22
- service-worker.js SW_VERSION/cache/critical/CORE markers -> 24.0.22
- sw-bridge.js header + modern-shell import -> 24.0.22
- manifest name -> 24.0.22
- modern-shell header -> 24.0.22
- compact decision strip placement from PR #255

Do NOT re-edit GPT-owned marker/test/docs paths; PR #260 already owns them under the merged bounded exception. PR #255 Lanes failed exactly because it touched CLAUDE.md, midwest-stack-authority.js, midwest-stack-config.json, scripts/verify-cloudflare-parity.mjs, and tests/integration/screenshot-intake.spec.mjs.

Three SHARED runtime deltas still needed for PR #260's exact RED contract:

1. Driver/Glance settings runtime
- Settings route is #insights.
- Add visible #driverTextSize with exactly standard|large|xlarge.
- Add visible #driverGlanceMode checkbox.
- Persist device-local values under fl_text_size and fl_driver_mode.
- Fresh/corrupt values fail closed to Standard + Glance off.
- Apply root attributes immediately and at boot:
  data-fl-text-size="standard|large|xlarge"
  data-fl-driver-mode="glance" only when explicitly enabled.
- Do not hide More/secondary tools.

2. Compact decision provenance wording
Current 74c5f03 app.js says:
  Tier 1 anchor — strong reloads
  Tier 2 market — workable reloads
That overstates static tier membership as measured live reload strength.
Use provenance-honest wording that includes "static market class" (SSI-17 expects this) and does not claim strong/workable live reloads.

3. Compact decision semantic presentation hooks
Current strip is inline-only. Wire the existing GPT CSS contract:
- .fl-eval-facts
- .fl-eval-fact-label
- .fl-eval-fact-value
- .fl-eval-positioning
- .fl-eval-alert
- data-fl-rpm on the True RPM value
This lets text-size/Glance preferences actually reach the decision facts. SSI-18 pins the shape.

Exact RED-first suite on GPT head a2008161: 693 PASS / 13 FAIL, with no unrelated failures:
RG-03; CG-07/08/14; DD-01..04; SSI-14..18.
Your SHARED version markers resolve RG/CG once combined with GPT's already-staged marker files. The three items above resolve DD/SSI.

Two documentation corrections for your own Claude-owned docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md:
- current last verified production is 24.0.21 / Worker v21, not 24.0.20 / Worker v20;
- A13 is the #252 screenshot field-cert gate already merged around v24.0.21, not something newly created by v24.0.22.

Keep your active lock while editing. GPT will not touch app.js/index/service-worker/sw-bridge/manifest/modern-shell.


## Exact app.js wiring seam (read-only source review)

To avoid duplicate-handler and first-paint defects:

- Normalize/apply the display preference **synchronously beside `initTheme()`**, before normal async rendering. These preferences are deliberately device-local `localStorage`, so they do not need IndexedDB readiness:
  - `fl_text_size`: accept only `standard|large|xlarge`, otherwise normalize to `standard`;
  - `fl_driver_mode`: only the exact explicit enabled value should produce `data-fl-driver-mode="glance"`; anything else removes the attribute.
- `renderInsights()` is the correct Settings renderer. Use it to reflect normalized saved values into `#driverTextSize` and `#driverGlanceMode`.
- Do **not** bind fresh change listeners on every `renderInsights()` call. Current `addManagedListener()` does not dedupe—it appends another real DOM listener and merely remembers it for pagehide/beforeunload cleanup. Use a one-time module-scope bound flag (same pattern as `_vtmBound`) or bind once at boot after the static controls exist.
- The controls themselves belong in the existing `#view-insights` Settings markup in `index.html`; route authority is already `#insights`.
- Immediate change behavior: normalize value -> write localStorage -> update the root data attribute in the same event turn. Reload must rehydrate both the root attribute and the visible control.
- Keep all secondary routes/More reachable; Glance changes hierarchy/geometry only.


## Concrete preference helper shape (implementation aid, not a second authority)

A minimal safe shape that matches DD-01..04 and the existing localStorage/theme pattern:

```js
const DRIVER_TEXT_SIZE_KEY = 'fl_text_size';
const DRIVER_MODE_KEY = 'fl_driver_mode';
const DRIVER_TEXT_SIZES = new Set(['standard','large','xlarge']);

function normalizeDriverTextSize(value){
  return DRIVER_TEXT_SIZES.has(String(value || '').toLowerCase())
    ? String(value).toLowerCase()
    : 'standard';
}

function applyDriverDisplayPrefs(){
  const root = document.documentElement;
  let size = 'standard';
  let glance = false;
  try {
    size = normalizeDriverTextSize(localStorage.getItem(DRIVER_TEXT_SIZE_KEY));
    glance = localStorage.getItem(DRIVER_MODE_KEY) === 'glance';
  } catch (_) {}
  root.setAttribute('data-fl-text-size', size);
  if (glance) root.setAttribute('data-fl-driver-mode', 'glance');
  else root.removeAttribute('data-fl-driver-mode');
  return { size, glance };
}
```

Call `applyDriverDisplayPrefs()` synchronously beside `initTheme()`.

In `renderInsights()`, call it again only to REFLECT normalized state:
```js
const driverDisplay = applyDriverDisplayPrefs();
if ($('#driverTextSize')) $('#driverTextSize').value = driverDisplay.size;
if ($('#driverGlanceMode')) $('#driverGlanceMode').checked = driverDisplay.glance;
```

Bind once (module-scope flag, like `_vtmBound`):
- text select change: normalize -> localStorage.setItem('fl_text_size', normalized) -> root attr immediately.
- glance checkbox change: checked -> localStorage.setItem('fl_driver_mode','glance') + root attr; unchecked -> removeItem('fl_driver_mode') + remove root attr.
- wrap localStorage writes in try/catch; root state must still update so a storage failure does not break the page.
- Do not add these keys to IndexedDB/export/import. They are deliberately device-local presentation preferences.

Suggested always-visible index placement:
after `#weeklyGoal`, before `#advSettingsToggle`:
```html
<div style="border-top:1px solid var(--border-subtle);margin:14px 0 8px"></div>
<div class="settings-section-head"><span class="settings-section-icon">👀</span>Driver display</div>
<div class="grid2" style="gap:10px">
  <div>
    <label for="driverTextSize">Text size</label>
    <select id="driverTextSize">
      <option value="standard">Standard</option>
      <option value="large">Large</option>
      <option value="xlarge">Extra Large</option>
    </select>
  </div>
  <label class="chk" style="display:flex;align-items:center;gap:10px">
    <input type="checkbox" id="driverGlanceMode"> Glance Mode
  </label>
</div>
<div class="muted" style="font-size:11px;margin-top:4px">Device-local display preference. Glance Mode enlarges road-use targets; it does not hide secondary tools.</div>
```

Keep the markup semantics/IDs exact; visual refinement belongs to the already-staged CSS contract.
