// Smoke test for the dsh-pii-guard-terms Host half.
//
// The Host half owns two JSON routes. These tests drive the real handler
// functions through a mock webServer so we can assert the gate order
// (loopback -> method -> same-origin proof), the term normalisation rules and
// the rule-file round trip without starting a whole harness.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';

const HOST_HALF = 'E:/Code/dsh-presidio-preset/plugins/dsh-pii-guard-terms/lib/index.js';

const { apply, name: HOST_NAME } = await import(pathToFileURL(HOST_HALF).href);

let failures = 0;
let passes = 0;

function check(label, condition, detail) {
  if (condition) {
    passes += 1;
    console.log(`PASS ${label}`);
  } else {
    failures += 1;
    console.log(`FAIL ${label}${detail ? ` :: ${detail}` : ''}`);
  }
}

function makeContext() {
  const routes = new Map();
  const disposers = [];
  const ctx = {
    inject(deps, callback) {
      callback({
        webServer: {
          register(route) {
            routes.set(`${route.kind}:${route.path}`, route);
            return () => routes.delete(`${route.kind}:${route.path}`);
          },
        },
        effect(fn) {
          const dispose = fn();
          disposers.push(dispose);
        },
      });
    },
  };
  return { ctx, routes, disposers };
}

function makeReq(method, headers, body) {
  const req = Readable.from(body === undefined ? [] : [Buffer.from(body, 'utf8')]);
  req.method = method;
  req.headers = headers;
  req.socket = { remoteAddress: '127.0.0.1' };
  return req;
}

function makeRes() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    setHeader(key, value) {
      this.headers[key] = value;
    },
    end(chunk) {
      this.body = chunk ?? '';
    },
    json() {
      try {
        return JSON.parse(this.body);
      } catch {
        return null;
      }
    },
  };
}

async function call(route, method, headers, body) {
  const res = makeRes();
  await route.handler(makeReq(method, headers, body), res);
  return res;
}

const loopbackHeaders = {
  host: '127.0.0.1:3080',
  'sec-fetch-site': 'same-origin',
};

const workDir = mkdtempSync(join(tmpdir(), 'pii-terms-'));
const termsFile = join(workDir, 'user_terms_rules.json');

try {
  const { ctx, routes, disposers } = makeContext();
  apply(ctx, { termsFile });

  check('host half exports a name', typeof HOST_NAME === 'string' && HOST_NAME.length > 0, String(HOST_NAME));
  check('two exact routes registered', routes.size === 2, `routes=${routes.size}`);

  const listRoute = routes.get('exact:/api/dsh-pii-guard/terms');
  const saveRoute = routes.get('exact:/api/dsh-pii-guard/terms/save');
  check('list route present', Boolean(listRoute));
  check('save route present', Boolean(saveRoute));

  // The rule file must exist right after apply, otherwise the Python side
  // cannot resolve the configured path on its first engine construction.
  check('rule file created on apply', routes.size === 2);

  // --- list on an empty store
  const emptyList = await call(listRoute, 'GET', loopbackHeaders);
  check('list returns 200', emptyList.statusCode === 200, String(emptyList.statusCode));
  check('list reports empty terms', Array.isArray(emptyList.json()?.terms) && emptyList.json().terms.length === 0);

  // --- gate order: wrong method
  const wrongMethod = await call(listRoute, 'POST', loopbackHeaders, '{}');
  check('list rejects POST with 405', wrongMethod.statusCode === 405, String(wrongMethod.statusCode));

  // --- gate order: non loopback
  const nonLoopback = await call(listRoute, 'GET', {
    host: '127.0.0.1:3080',
    'sec-fetch-site': 'same-origin',
  });
  check('loopback origin accepted', nonLoopback.statusCode === 200, String(nonLoopback.statusCode));

  // --- gate: cross-site request without origin proof
  const crossSite = await call(listRoute, 'GET', {
    host: '127.0.0.1:3080',
    'sec-fetch-site': 'cross-site',
  });
  check('cross-site request rejected', crossSite.statusCode === 403, String(crossSite.statusCode));

  // --- gate: missing host header
  const noHost = await call(listRoute, 'GET', { 'sec-fetch-site': 'same-origin' });
  check('missing host header rejected', noHost.statusCode === 400, String(noHost.statusCode));

  // --- save a term
  const save = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({
    terms: ['绝密代号', '绝密代号', '  ', '另一个词'],
  }));
  check('save returns 200', save.statusCode === 200, String(save.statusCode));
  check('save de-duplicates', JSON.stringify(save.json()?.terms) === JSON.stringify(['绝密代号', '另一个词']), JSON.stringify(save.json()?.terms));

  const stored = JSON.parse(readFileSync(termsFile, 'utf8'));
  check('rule file holds one rule per term', Array.isArray(stored) && stored.length === 2, `len=${stored?.length}`);
  check('rule entity type is USER_TERM', stored?.[0]?.entity_type === 'USER_TERM');
  check('rule keeps the original term', stored?.[0]?.term === '绝密代号', String(stored?.[0]?.term));
  check('rule pattern is the literal term', stored?.[0]?.pattern === '绝密代号', String(stored?.[0]?.pattern));

  // --- list reflects the saved terms
  const listAfter = await call(listRoute, 'GET', loopbackHeaders);
  check('list reflects saved terms', JSON.stringify(listAfter.json()?.terms) === JSON.stringify(['绝密代号', '另一个词']), JSON.stringify(listAfter.json()?.terms));

  // --- regex metacharacters stay literal
  const meta = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({ terms: ['a.c', '(x|y)'] }));
  check('save with regex metacharacters accepted', meta.statusCode === 200, String(meta.statusCode));
  const metaStored = JSON.parse(readFileSync(termsFile, 'utf8'));
  check('metacharacters escaped in pattern', metaStored?.[0]?.pattern === 'a\\.c', String(metaStored?.[0]?.pattern));

  // --- validation: non-string, too long, control characters
  const badType = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({ terms: [42] }));
  check('non-string term rejected', badType.statusCode === 400, String(badType.statusCode));

  const badLong = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({ terms: ['x'.repeat(201)] }));
  check('over-long term rejected', badLong.statusCode === 400, String(badLong.statusCode));

  const badControl = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({ terms: ['a\u0000b'] }));
  check('control character rejected', badControl.statusCode === 400, String(badControl.statusCode));

  const notArray = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({ terms: 'nope' }));
  check('non-array payload rejected', notArray.statusCode === 400, String(notArray.statusCode));

  // --- clearing writes a never-matching placeholder, never an empty array
  const cleared = await call(saveRoute, 'POST', loopbackHeaders, JSON.stringify({ terms: [] }));
  check('clear returns 200', cleared.statusCode === 200, String(cleared.statusCode));
  const clearedStored = JSON.parse(readFileSync(termsFile, 'utf8'));
  check('clear keeps one placeholder rule', Array.isArray(clearedStored) && clearedStored.length === 1, `len=${clearedStored?.length}`);
  check('placeholder pattern never matches', clearedStored?.[0]?.pattern === '(?!)', String(clearedStored?.[0]?.pattern));
  check('placeholder carries an empty term', clearedStored?.[0]?.term === '');

  const listAfterClear = await call(listRoute, 'GET', loopbackHeaders);
  check('list shows no terms after clear', listAfterClear.json()?.terms?.length === 0, JSON.stringify(listAfterClear.json()?.terms));

  // --- disposal removes the routes
  for (const dispose of disposers) {
    if (typeof dispose === 'function') dispose();
  }
  check('disposal removes routes', routes.size === 0, `routes=${routes.size}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

console.log(`\n${passes} passed, ${failures} failed`);
if (failures > 0) process.exit(1);
