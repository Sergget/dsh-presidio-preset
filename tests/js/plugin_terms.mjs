// Smoke test for the dsh-pii-guard-terms Host half.
//
// The Host half owns four JSON routes: two for the terms blocklist and two
// for the P0/P1 runtime settings. These tests drive the real handlers through
// a mock webServer to assert gate order (loopback -> method -> same-origin
// proof), term normalisation, settings validation and the rule-file round
// trip without starting a whole harness.
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
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

// The desktop shell sends no Sec-Fetch-Site, only the real DSH session cookie.
function sessionCookieFor(host) {
  const authority = new URL(`http://${host}`).host;
  const digest = createHash('sha256').update(authority).digest();
  const encoded = digest.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
  return `dsh-auth-${encoded}=legit-session-value`;
}

const workDir = mkdtempSync(join(tmpdir(), 'pii-terms-'));
const termsFile = join(workDir, 'user_terms_rules.json');
const settingsFile = join(workDir, 'guard-settings.json');
const presetFile = join(workDir, 'preset.json');
// Point the preset at the SAME terms file so the S2 drift guard stays silent.
writeFileSync(presetFile, JSON.stringify({
  name: 'presidio-pii',
  version: '0.1.0',
  config: { custom_rules_path: termsFile.replaceAll('\\', '/'), whitelist_path: null },
  entity_types: ['PHONE_NUMBER', 'PERSON'],
}));

try {
  const { ctx, routes, disposers } = makeContext();
  apply(ctx, { termsFile, settingsFile, presetFile });

  check('host half exports a name', typeof HOST_NAME === 'string' && HOST_NAME.length > 0, String(HOST_NAME));
  check('six exact routes registered', routes.size === 6, `routes=${routes.size}`);

  const listRoute = routes.get('exact:/api/dsh-pii-guard/terms');
  const saveRoute = routes.get('exact:/api/dsh-pii-guard/terms/save');
  const settingsGet = routes.get('exact:/api/dsh-pii-guard/settings');
  const settingsSave = routes.get('exact:/api/dsh-pii-guard/settings/save');
  const presetGet = routes.get('exact:/api/dsh-pii-guard/preset');
  const presetSave = routes.get('exact:/api/dsh-pii-guard/preset/save');
  check('list route present', Boolean(listRoute));
  check('save route present', Boolean(saveRoute));
  check('settings get route present', Boolean(settingsGet));
  check('settings save route present', Boolean(settingsSave));
  check('preset get route present', Boolean(presetGet));
  check('preset save route present', Boolean(presetSave));

  // The rule file must exist right after apply, otherwise the Python side
  // cannot resolve the configured path on its first engine construction.
  check('rule file created on apply', existsSync(termsFile));

  // --- list on an empty store
  const emptyList = await call(listRoute, 'GET', loopbackHeaders);
  check('list returns 200', emptyList.statusCode === 200, String(emptyList.statusCode));
  check('list reports empty terms', Array.isArray(emptyList.json()?.terms) && emptyList.json().terms.length === 0);

  // --- gate order: wrong method
  const wrongMethod = await call(listRoute, 'POST', loopbackHeaders, '{}');
  check('list rejects POST with 405', wrongMethod.statusCode === 405, String(wrongMethod.statusCode));

  // --- gate: cross-site request without origin proof
  const crossSite = await call(listRoute, 'GET', {
    host: '127.0.0.1:3080',
    'sec-fetch-site': 'cross-site',
  });
  check('cross-site request rejected', crossSite.statusCode === 403, String(crossSite.statusCode));

  // --- gate: missing host header
  const noHost = await call(listRoute, 'GET', { 'sec-fetch-site': 'same-origin' });
  check('missing host header rejected', noHost.statusCode === 400, String(noHost.statusCode));

  // --- S1: no fetch headers, only a real DSH session cookie -> accepted
  const cookieHeaders = { host: '127.0.0.1:3080', cookie: sessionCookieFor('127.0.0.1:3080') };
  const cookieOk = await call(listRoute, 'GET', cookieHeaders);
  check('valid session cookie accepted without fetch headers', cookieOk.statusCode === 200, String(cookieOk.statusCode));

  // --- S1: a forged arbitrary cookie must NOT count as same-origin proof
  const forgedCookie = await call(listRoute, 'GET', {
    host: '127.0.0.1:3080',
    cookie: 'foo=1',
  });
  check('forged arbitrary cookie rejected (S1)', forgedCookie.statusCode === 403, String(forgedCookie.statusCode));

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

  // --- settings: defaults, save, round-trip, validation
  const settingsEmpty = await call(settingsGet, 'GET', loopbackHeaders);
  check('settings get returns 200', settingsEmpty.statusCode === 200, String(settingsEmpty.statusCode));
  check('settings has four keys', ['displayMode', 'failOpen', 'shellDisabled', 'shellAllowlist'].every((k) => Object.hasOwn(settingsEmpty.json()?.settings ?? {}, k)), JSON.stringify(settingsEmpty.json()?.settings));

  const settingsWrite = await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({
    settings: { displayMode: 'mask', failOpen: true, shellDisabled: true, shellAllowlist: '^pwsh ' },
  }));
  check('settings save returns 200', settingsWrite.statusCode === 200, String(settingsWrite.statusCode));
  check('settings save echoes values', settingsWrite.json()?.settings?.displayMode === 'mask' && settingsWrite.json()?.settings?.failOpen === true, JSON.stringify(settingsWrite.json()?.settings));

  const settingsRead = await call(settingsGet, 'GET', loopbackHeaders);
  check('settings persisted to disk', settingsRead.json()?.settings?.displayMode === 'mask' && existsSync(settingsFile));
  const diskSettings = JSON.parse(readFileSync(settingsFile, 'utf8'));
  check('settings file has exactly four keys', Object.keys(diskSettings).sort().join(',') === 'displayMode,failOpen,shellAllowlist,shellDisabled', Object.keys(diskSettings).join(','));

  const badMode = await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({ settings: { displayMode: 'banana' } }));
  check('invalid displayMode rejected', badMode.statusCode === 400, String(badMode.statusCode));
  const badRegex = await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({ settings: { shellAllowlist: '([ ' } }));
  check('invalid regex rejected', badRegex.statusCode === 400, String(badRegex.statusCode));

  // --- ReDoS: a nested quantifier would freeze the post-execute hook, so the
  // settings endpoint must refuse the pattern before it ever reaches readSettings.
  const redos = await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({ settings: { shellAllowlist: '^(a+)+$' } }));
  check('nested quantifier rejected (ReDoS)', redos.statusCode === 400, `status=${redos.statusCode} body=${JSON.stringify(redos.json())}`);
  const redosAlt = await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({ settings: { shellAllowlist: '(a|a)+' } }));
  check('overlapping alternation rejected (ReDoS)', redosAlt.statusCode === 400, String(redosAlt.statusCode));
  // A benign pattern with an escaped paren / chars in a class must still pass.
  const benign = await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({ settings: { shellAllowlist: '^\\(safe\\).*[(+)]$' } }));
  check('escaped parens and char class allowed', benign.statusCode === 200, `status=${benign.statusCode} body=${JSON.stringify(benign.json())}`);
  // Restore a clean allowlist so the earlier persisted state does not leak.
  await call(settingsSave, 'POST', loopbackHeaders, JSON.stringify({ settings: { shellAllowlist: '' } }));

  const settingsForbidden = await call(settingsSave, 'POST', { host: '127.0.0.1:3080', cookie: 'foo=1' }, JSON.stringify({ settings: {} }));
  check('forged cookie cannot save settings (S1)', settingsForbidden.statusCode === 403, String(settingsForbidden.statusCode));

  // --- preset: entity types + whitelist path (the Python engine reads both)
  const presetRead = await call(presetGet, 'GET', loopbackHeaders);
  check('preset get returns 200', presetRead.statusCode === 200, String(presetRead.statusCode));
  check('preset get reports configured entity types',
    JSON.stringify(presetRead.json()?.preset?.entityTypes) === JSON.stringify(['PHONE_NUMBER', 'PERSON']),
    JSON.stringify(presetRead.json()?.preset?.entityTypes));
  check('preset get offers the known entity type list',
    Array.isArray(presetRead.json()?.preset?.knownEntityTypes) && presetRead.json().preset.knownEntityTypes.includes('ORGANIZATION'),
    JSON.stringify(presetRead.json()?.preset?.knownEntityTypes));
  check('preset get reports a null whitelist path', presetRead.json()?.preset?.whitelistPath === '', JSON.stringify(presetRead.json()?.preset?.whitelistPath));

  const presetWrite = await call(presetSave, 'POST', loopbackHeaders, JSON.stringify({
    preset: { entityTypes: ['PERSON', 'PHONE_NUMBER'], whitelistPath: './whitelist.txt' },
  }));
  check('preset save returns 200', presetWrite.statusCode === 200, `status=${presetWrite.statusCode} body=${JSON.stringify(presetWrite.json())}`);
  check('preset save echoes entity types',
    JSON.stringify(presetWrite.json()?.preset?.entityTypes) === JSON.stringify(['PERSON', 'PHONE_NUMBER']),
    JSON.stringify(presetWrite.json()?.preset?.entityTypes));

  const presetOnDisk = JSON.parse(readFileSync(presetFile, 'utf8'));
  check('preset keeps untouched fields (name)', presetOnDisk.name === 'presidio-pii', String(presetOnDisk.name));
  check('preset keeps untouched config fields',
    presetOnDisk.config?.custom_rules_path === termsFile.replaceAll('\\', '/'),
    String(presetOnDisk.config?.custom_rules_path));
  check('preset writes whitelist_path into config', presetOnDisk.config?.whitelist_path === './whitelist.txt', String(presetOnDisk.config?.whitelist_path));
  check('preset writes entity_types at top level', JSON.stringify(presetOnDisk.entity_types) === JSON.stringify(['PERSON', 'PHONE_NUMBER']), JSON.stringify(presetOnDisk.entity_types));

  const presetUnknownType = await call(presetSave, 'POST', loopbackHeaders, JSON.stringify({ preset: { entityTypes: ['NOT_A_TYPE'] } }));
  check('unknown entity type rejected', presetUnknownType.statusCode === 400, String(presetUnknownType.statusCode));
  const presetBadArray = await call(presetSave, 'POST', loopbackHeaders, JSON.stringify({ preset: { entityTypes: 'PERSON' } }));
  check('non-array entityTypes rejected', presetBadArray.statusCode === 400, String(presetBadArray.statusCode));
  const presetBadPath = await call(presetSave, 'POST', loopbackHeaders, JSON.stringify({ preset: { whitelistPath: 'relative/without/dot' } }));
  check('relative whitelist path rejected', presetBadPath.statusCode === 400, String(presetBadPath.statusCode));
  const presetClear = await call(presetSave, 'POST', loopbackHeaders, JSON.stringify({ preset: { whitelistPath: null } }));
  check('null whitelist path clears it', presetClear.statusCode === 200 && presetClear.json()?.preset?.whitelistPath === '', `status=${presetClear.statusCode} body=${JSON.stringify(presetClear.json())}`);

  const presetForbidden = await call(presetSave, 'POST', { host: '127.0.0.1:3080', cookie: 'foo=1' }, JSON.stringify({ preset: { entityTypes: [] } }));
  check('forged cookie cannot save preset (S1)', presetForbidden.statusCode === 403, String(presetForbidden.statusCode));
  const presetWrongMethod = await call(presetGet, 'POST', loopbackHeaders, '{}');
  check('preset get rejects POST with 405', presetWrongMethod.statusCode === 405, String(presetWrongMethod.statusCode));

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
