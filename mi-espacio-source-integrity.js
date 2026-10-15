'use strict';

// The authenticated personal-context endpoint must not report partial, failed
// database reads as a verified empty staff timeline or research portfolio.
// This helper inspects only response metadata; it never receives identity tokens
// or serializes clinical records into logs or HTTP errors.
function unavailableSources(sources) {
  return sources.filter(({name, result, shape}) =>
    !name || !result || result.error ||
    !Object.prototype.hasOwnProperty.call(result, 'data') ||
    (shape === 'list' && !Array.isArray(result.data))
  ).map(({name, result}) => ({
    source: String(name || 'unknown'),
    code: String(result?.error?.code || 'INVALID_SOURCE_RESPONSE').slice(0, 32)
  }));
}

function sendUnavailable(res, failures) {
  // Safe operational diagnostics: source names + codes only, no IDs, names,
  // row contents, SQL text, or database error details.
  console.error('Mi Espacio personal-context sources unavailable:', failures);
  return res.status(503).json({
    error: 'MI_ESPACIO_SOURCE_UNAVAILABLE',
    message: 'No se puede consultar toda tu actividad en este momento. Vuelve a intentarlo.'
  });
}

module.exports = { unavailableSources, sendUnavailable };
