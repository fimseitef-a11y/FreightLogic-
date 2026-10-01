function asUniqueStrings(values, label) {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  return [...new Set(values.map((value) => String(value)).filter(Boolean))];
}

export function evaluateSourceDegradation({ sources, removedSourceId, requiredComponents } = {}) {
  if (!Array.isArray(sources)) throw new TypeError('sources must be an array');
  const components = asUniqueStrings(requiredComponents, 'requiredComponents');
  const removed = removedSourceId == null ? null : String(removedSourceId);

  const eligibleSources = sources.filter((source) => {
    if (!source || typeof source !== 'object') return false;
    if (removed && source.sourceId === removed) return false;
    return source.available !== false;
  });

  const componentState = {};
  for (const component of components) {
    const providers = eligibleSources.filter(
      (source) => Array.isArray(source.components) && source.components.includes(component),
    );

    if (providers.length === 0) {
      componentState[component] = {
        status: 'UNKNOWN',
        reason: 'SOURCE_UNAVAILABLE',
        sourceId: null,
        sourceIds: [],
        confidence: null,
      };
      continue;
    }

    componentState[component] = {
      status: 'KNOWN',
      reason: null,
      sourceId: providers.length === 1 ? providers[0].sourceId : null,
      sourceIds: providers.map((source) => source.sourceId),
      confidence: null,
    };
  }

  return {
    queryable: true,
    removedSourceId: removed,
    components: componentState,
    syntheticReplacementUsed: false,
  };
}
