import { launchBlank, createSuite, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/field-certification-runner.spec.mjs');

test('[FIELD CERT / NEW] FC-01 runner loads and exposes exactly A1-A12 as NOT_RUN', async () => {
  const app = await launchBlank();
  try {
    const response = await app.page.goto(`${app.baseUrl}/field-certification.html`, { waitUntil: 'load' });
    eq(response?.status(), 200, 'field certification companion must be served from the FreightLogic origin');

    const gates = await app.page.locator('[data-gate]').evaluateAll(nodes => nodes.map(node => ({
      id: node.getAttribute('data-gate'),
      status: node.getAttribute('data-status'),
    })));
    eq(gates.length, 12, 'the companion must render exactly the twelve physical-device gates');
    eq(gates.map(g => g.id).join(','), 'A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12',
      'the companion must preserve the canonical A1-A12 identity and order');
    eq(gates.every(g => g.status === 'NOT_RUN'), true,
      'every physical-device gate must start in the canonical NOT_RUN state; nothing is pre-certified');
  } finally {
    await app.close();
  }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await run();
  process.exit(result.fail ? 1 : 0);
}
