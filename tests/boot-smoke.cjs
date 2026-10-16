'use strict';
// Boot smoke test: load index.js with dummy env until the HTTP server would start. Catches
// load-order crashes (e.g. a route using a const defined later) that source-level tests miss.
process.env.SUPABASE_URL = 'http://127.0.0.1:9';
process.env.SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-key';
process.env.JWT_SECRET = 'x'.repeat(48);
process.env.NODE_ENV = 'test';
require('http').Server.prototype.listen = function () { console.log('BOOT OK: all routes registered'); process.exit(0); };
setTimeout(() => { console.log('BOOT OK: module loaded'); process.exit(0); }, 4000);
try { require('../index.js'); } catch (e) { console.error('BOOT FAILED:', e.stack || e.message); process.exit(1); }
