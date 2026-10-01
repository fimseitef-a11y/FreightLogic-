import { normalizeEvidence } from './normalize.mjs';

function resolveComponent(evidence, component, allowedSourceClasses) {
  const componentRows = evidence.filter((row) =>
    row.component === component && allowedSourceClasses.has(row.sourceClass) && row.eligible,
  );

  const usable = componentRows.filter((row) =>
    Number.isFinite(row.value) && row.freshnessState !== 'STALE' && row.freshnessState !== 'UNAVAILABLE',
  );

  if (usable.length === 0) {
    const stale = componentRows.some((row) => row.freshnessState === 'STALE');
    return {
      value: null,
      status: 'UNKNOWN',
      unknownFlag: stale ? `${component.toUpperCase()}_EVIDENCE_STALE` : `${component.toUpperCase()}_EVIDENCE_MISSING`,
      conflictFlag: null,
    };
  }

  const distinct = [...new Set(usable.map((row) => row.value))];
  if (distinct.length !== 1) {
    return {
      value: null,
      status: 'UNKNOWN',
      unknownFlag: null,
      conflictFlag: `${component.toUpperCase()}_EVIDENCE_CONFLICT`,
    };
  }

  return { value: distinct[0], status: 'KNOWN', unknownFlag: null, conflictFlag: null };
}

export function deriveLaneIntelligence(rawEvidence = []) {
  const evidence = Array.isArray(rawEvidence) ? rawEvidence.map(normalizeEvidence) : [];
  const structural = resolveComponent(evidence, 'structural', new Set(['STRUCTURAL_PUBLIC']));
  const expedite = resolveComponent(
    evidence,
    'expedite',
    new Set(['STRUCTURAL_PUBLIC', 'LICENSED_LIVE_OPTIONAL']),
  );

  const operatorRows = evidence.filter((row) => row.sourceClass === 'OPERATOR_PRIVATE');
  const unknownFlags = [structural.unknownFlag, expedite.unknownFlag].filter(Boolean);
  const conflictFlags = [structural.conflictFlag, expedite.conflictFlag].filter(Boolean);

  return {
    structuralScore: structural.value,
    structuralStatus: structural.status,
    expediteRelevance: expedite.value,
    expediteStatus: expedite.status,
    unknownFlags,
    conflictFlags,
    operatorOverlay: {
      evidenceCount: operatorRows.length,
    },
  };
}
