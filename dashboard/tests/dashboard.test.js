'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

const SAMPLE_STAGES = { stages: ['source', 'build', 'test', 'scan', 'sign', 'publish', 'deploy'] };

// GET /api/v1/stats is where the summary cards and the stage strip now
// get their numbers -- fleet-wide, from the server, because
// /api/v1/artifacts is paginated and counting one page of it produced
// cards that read as totals and meant "of these 50".
//
// These values are exactly what SAMPLE_ARTIFACTS below would have
// computed back when the dashboard counted them client-side, so the
// card and stage-pill assertions throughout this file are unchanged: 3
// artifacts, one scanning, one with an active CVE, one with active
// malware, and stages scan/build/unstaged one each.
//
// Note by_stage's EMPTY-STRING key for the unstaged artifact -- not
// "unassigned". The stage list is deployment configuration, so the API
// won't invent a name that could collide with a real stage; the
// "unassigned" label is the dashboard's own (see renderStages).
const SAMPLE_STATS = {
  total: 3,
  by_status: { scanned: 2, scanning: 1 },
  by_type: { image: 2, file: 1 },
  with_findings: { cve: 1, malware: 1, misconfiguration: 0, secret: 0, other: 0 },
  by_stage: { scan: 1, build: 1, '': 1 }
};

// statsFor builds a /api/v1/stats body for the handful of tests that
// supply their own one-artifact list instead of SAMPLE_ARTIFACTS. Only
// the bucket counts ever differ between them, so that's all it takes --
// what those tests are checking is that each card reads the bucket it
// claims to (the cards are positional, and swapping "With secrets" for
// "With misconfigurations" would be invisible if every bucket were 1).
function statsFor(buckets) {
  return {
    total: 1,
    by_status: { scanned: 1 },
    by_type: {},
    with_findings: Object.assign(
      { cve: 0, malware: 0, misconfiguration: 0, secret: 0, other: 0 },
      buckets
    ),
    by_stage: {}
  };
}

const SAMPLE_ARTIFACTS = [
  {
    id: 'a1',
    ref: 'alpine:3.19',
    type: 'image',
    status: 'scanned',
    current_stage: 'scan',
    digest: 'sha256:abc123',
    stage_history: [
      { stage: 'build', timestamp: '2026-07-19T10:00:00Z', note: 'CI job #1' },
      { stage: 'scan', timestamp: '2026-07-19T10:05:00Z' }
    ],
    cve_findings: [{ id: 'CVE-2024-1234', severity: 'high', title: 'openssl bug', source: 'trivy' }],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-19T09:00:00Z',
    updated_at: '2026-07-19T10:05:00Z',
    last_scan_at: '2026-07-19T10:05:00Z'
  },
  {
    id: 'a2',
    ref: '/tmp/suspicious.bin',
    type: 'file',
    status: 'scanned',
    current_stage: '',
    stage_history: [],
    cve_findings: [],
    malware_findings: [{ id: 'clamav-signature-match', severity: 'critical', title: 'Eicar-Test-Signature', source: 'clamav' }],
    last_scan_errors: [],
    created_at: '2026-07-19T09:00:00Z',
    updated_at: '2026-07-19T09:30:00Z'
  },
  {
    id: 'a3',
    ref: 'ghcr.io/example/app:latest',
    type: 'image',
    status: 'scanning',
    current_stage: 'build',
    stage_history: [],
    cve_findings: [],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-19T11:00:00Z',
    updated_at: '2026-07-19T11:00:00Z'
  }
];

// GET /api/v1/artifacts is paginated server-side: the dashboard asks
// for `?limit=50&offset=0` (plus any status/type filter) and reads a
// {total, artifacts} object rather than a bare array. These two helpers
// keep every mock below matching the real URL shape and returning the
// real body shape.
function isArtifactsList(url) {
  return /\/api\/v1\/artifacts(\?|$)/.test(url);
}

function artifactsPage(list) {
  return jsonResponse({ total: list.length, artifacts: list });
}

function jsonResponse(data) {
  return Promise.resolve({
    ok: true,
    status: 200,
    statusText: 'OK',
    json: () => Promise.resolve(data)
  });
}

function errorResponse(status, body) {
  return Promise.resolve({
    ok: false,
    status,
    statusText: 'Error',
    json: () => Promise.resolve(body)
  });
}

// Waits for loadAll()'s mocked-fetch chain (fetchJSON -> fetchJSON ->
// render, a handful of already-resolved promises, no real I/O) to
// finish, then some. The 20ms every call site here originally passed
// was tuned against a fast, idle dev machine -- it passed 18/18 locally
// in exactly that kind of environment, then failed on its first real
// GitHub Actions run with every early assertion seeing pre-render state
// ('', [], wrong status class), the signature of the assertion running
// before loadAll() finished rather than of anything actually wrong with
// the dashboard's own logic. Shared CI runners plus jsdom/V8 startup
// overhead inside a freshly started container can by themselves eat
// into a 20ms budget before the mocked promise chain even gets to run.
// Flushing the microtask queue a few times first (cheap, and directly
// targets "loadAll's own await chain hasn't settled yet") plus a floor
// under whatever ms a call site passes (some callers already asked for
// more than 20ms further down this file) makes this robust across
// environments instead of tuned to whichever machine last ran it.
async function tick(ms) {
  for (let i = 0; i < 10; i++) await Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, Math.max(ms, 150)));
}

function buildDom({ url, fetchImpl, beforeParseExtra }) {
  return new JSDOM(html, {
    url,
    runScripts: 'dangerously',
    // Deliberately NOT 'usable': that makes jsdom actually attempt real
    // network fetches for index.html's external <link>/<script src>
    // tags (the tabler-icons CDN stylesheet, env.js) in every one of
    // these ~18 windows. Neither is needed for what's under test --
    // window.SCM_CONFIG (what env.js sets in production) is injected
    // directly via beforeParseExtra below wherever a test needs it, and
    // the icon font is irrelevant to any assertion here. On a machine
    // with real, unrestricted internet access (unlike a locked-down
    // sandbox, where these just fail fast), 'usable' turned this into a
    // real cause of the whole test run hanging indefinitely: real
    // HTTPS/HTTP connections that can outlive dom.window.close() and
    // keep Node's event loop from ever going idle, so the process never
    // exits on its own.
    pretendToBeVisual: true,
    beforeParse(window) {
      // Injected before the inline <script> runs, so the very first
      // loadAll() call (fired immediately on page load) sees this mock
      // instead of making a real network request.
      window.fetch = fetchImpl;
      if (beforeParseExtra) beforeParseExtra(window);
    }
  });
}

// The regression this endpoint exists to fix: /api/v1/artifacts is
// paginated, so a card counted from the rows on screen was capped at
// the page size while reading like a fleet total. Here the store has
// 812 artifacts and the page holds one, with numbers deliberately
// unreachable by counting that page -- if any card or stage pill is
// still computed client-side it reads 0 or 1, never these.
test('summary cards and stage pills come from /api/v1/stats, not the page on screen', async () => {
  const onePage = [SAMPLE_ARTIFACTS[0]];
  const fleet = {
    total: 812,
    by_status: { scanned: 780, scanning: 29, failed: 3 },
    by_type: { image: 812 },
    with_findings: { cve: 214, malware: 2, misconfiguration: 61, secret: 4, other: 33 },
    by_stage: { build: 300, scan: 402, '': 110 }
  };

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(fleet);
      if (isArtifactsList(url)) return artifactsPage(onePage);
      return errorResponse(404, { error: 'not found' });
    }
  });

  await tick(20);
  const doc = dom.window.document;

  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  // total, scanning, cve, malware, other, misconfiguration, secret,
  // then failed -- the card order is positional, so this also pins each
  // card to the bucket it's labelled with. "Failed scans" is last
  // because this fleet has failures (3); it is omitted entirely when
  // there are none.
  assert.deepEqual(cardNumbers, ['812', '29', '214', '2', '33', '61', '4', '3']);

  // Stage pills read by_stage, and the empty-string key becomes the
  // "unassigned" pill -- the API won't name that bucket itself, because
  // the stage list is deployment config and any name it invented could
  // collide with a real stage.
  const pills = [...doc.querySelectorAll('#stages .stage-pill')].map((p) => p.textContent);
  assert.ok(pills.includes('build300'), `expected a build pill of 300, got ${pills}`);
  assert.ok(pills.includes('scan402'), `expected a scan pill of 402, got ${pills}`);
  assert.ok(pills.includes('unassigned110'), `expected an unassigned pill of 110, got ${pills}`);
  // A configured stage nothing has reached is absent from by_stage
  // entirely, and must render as 0 rather than undefined.
  assert.ok(pills.includes('deploy0'), `expected a deploy pill of 0, got ${pills}`);

  // The table still shows only what the page actually contains -- the
  // cards being fleet-wide is exactly the point, but the rows are not.
  assert.equal(doc.querySelectorAll('#artifact-rows tr[data-id]').length, 1);

  dom.window.close();
});

test('renders artifact rows, summary cards, and stage pills from a live API response', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, { error: 'not found' });
    }
  });

  await tick(20);
  const doc = dom.window.document;

  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  // total, scanning, with CVEs, with malware, with other findings, with
  // misconfigurations, with secrets
  assert.deepEqual(cardNumbers, ['3', '1', '1', '1', '0', '0', '0']);

  const stageText = doc.getElementById('stages').textContent;
  for (const s of SAMPLE_STAGES.stages) assert.match(stageText, new RegExp(s));
  assert.match(stageText, /unassigned/);

  const rows = doc.querySelectorAll('#artifact-rows tr[data-id]');
  assert.equal(rows.length, 3);

  assert.equal(doc.getElementById('status').className, '');
  assert.match(doc.getElementById('status').textContent, /Connected/);

  dom.window.close();
});

test('Details navigates to the artifact detail page with last-scan/digest/CVE/malware metadata, and Back returns to the list', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.equal(doc.getElementById('detail-view').hidden, true, 'detail page starts hidden');

  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  assert.equal(doc.getElementById('detail-view').hidden, false, 'Details opens the detail page');
  assert.equal(doc.getElementById('list-view').hidden, true, 'the list hides while on the detail page');
  assert.equal(dom.window.location.hash, '#/artifacts/a1', 'the detail page is bookmarkable');

  const body = doc.getElementById('detail-body').innerHTML;
  assert.match(body, /Last scan/);
  assert.match(body, /sha256:abc123/, 'a1 has a resolved digest');
  assert.match(body, /openssl bug/);
  assert.match(body, /Not set/, 'a1 has no maintainer configured');
  assert.match(
    body,
    /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-1234"/,
    'a real CVE id gets a Read more link to NVD'
  );

  doc.querySelector('button[data-action="back"]').click();
  assert.equal(doc.getElementById('detail-view').hidden, true, 'Back closes the detail page');
  assert.equal(doc.getElementById('list-view').hidden, false, 'Back shows the list again');

  // a3 has no digest and no last_scan_at (still "scanning") -- the
  // unresolved/not-yet-scanned branch of the same page.
  doc.querySelector('button[data-action="toggle"][data-id="a3"]').click();
  const a3Body = doc.getElementById('detail-body').innerHTML;
  assert.match(a3Body, /not resolved/);
  assert.match(a3Body, /Not yet scanned/);

  // a2's only finding is malware (id "clamav-signature-match", not a
  // real CVE) -- it must not get an NVD link. Malware findings live
  // under their own tab (a fresh artifact id resets the tab to CVE), so
  // switch to it first.
  doc.querySelector('button[data-action="toggle"][data-id="a2"]').click();
  doc.querySelector('button[data-action="tab"][data-bucket="malware_findings"]').click();
  const a2Body = doc.getElementById('detail-body').innerHTML;
  assert.doesNotMatch(a2Body, /nvd\.nist\.gov/, 'a non-CVE finding id gets no Read more link');

  dom.window.close();
});

test('a bookmarked detail URL resolves once the artifact list loads, and an unknown id shows a not-found state', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/#/artifacts/a1',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.equal(doc.getElementById('detail-view').hidden, false, 'a hash-based URL opens straight to the detail page');
  assert.match(doc.getElementById('detail-body').innerHTML, /alpine:3\.19/);

  // Simulates the user editing the URL (or a browser back/forward) to
  // an id that isn't in state.artifacts -- must not render nothing.
  dom.window.location.hash = '#/artifacts/does-not-exist';
  await tick(20);
  assert.match(
    doc.getElementById('detail-body').innerHTML,
    /Artifact not found/,
    'a deleted or bad id gets a real empty state, not a blank page'
  );

  dom.window.close();
});

test('the detail page shows a download button only for documents that have actually been captured', async () => {
  const artifacts = [
    { id: 'd1', ref: 'alpine:3.19', type: 'image', status: 'scanned', current_stage: 'scan',
      cve_findings: [], malware_findings: [], created_at: '2026-07-19T09:00:00Z', updated_at: '2026-07-19T10:05:00Z',
      has_sbom: true, has_sarif: true },
    { id: 'd2', ref: 'busybox:latest', type: 'image', status: 'scanned', current_stage: 'scan',
      cve_findings: [], malware_findings: [], created_at: '2026-07-19T09:00:00Z', updated_at: '2026-07-19T09:30:00Z' }
  ];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(artifacts);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="d1"]').click();
  const d1Body = doc.getElementById('detail-body').innerHTML;
  assert.match(d1Body, /Download SBOM/);
  assert.match(d1Body, /Download SARIF report/);

  doc.querySelector('button[data-action="toggle"][data-id="d2"]').click();
  const d2Body = doc.getElementById('detail-body').innerHTML;
  assert.doesNotMatch(d2Body, /Download SBOM/);
  assert.doesNotMatch(d2Body, /Download SARIF report/);
  assert.match(d2Body, /Not yet generated/);

  dom.window.close();
});

test('clicking a document download button fetches it with the API key and triggers a save, without a plain <a href> (which would 401)', async () => {
  const artifacts = [
    { id: 'd1', ref: 'alpine:3.19', type: 'image', status: 'scanned', current_stage: 'scan',
      cve_findings: [], malware_findings: [], created_at: '2026-07-19T09:00:00Z', updated_at: '2026-07-19T10:05:00Z',
      has_sbom: true }
  ];
  let capturedRequest = null;
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(artifacts);
      if (url.endsWith('/api/v1/artifacts/d1/documents/sbom')) {
        capturedRequest = { url, headers: (opts && opts.headers) || {} };
        return Promise.resolve({
          ok: true,
          status: 200,
          blob: () => Promise.resolve(new dom.window.Blob(['{"bomFormat":"CycloneDX"}'], { type: 'application/vnd.cyclonedx+json' }))
        });
      }
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: 'test-key-123' };
      // jsdom has no createObjectURL/revokeObjectURL (confirmed against
      // this project's pinned jsdom version) -- stubbed here the same
      // way env.js/SCM_CONFIG is injected above, so the download path
      // itself is exercised without needing a real browser for this
      // part. The click-triggers-an-actual-file-save behavior this
      // enables in a real browser still needs live verification (see
      // this test's own title) -- jsdom can't observe an OS-level save
      // dialog either way.
      let created = 0, revoked = 0;
      window.URL.createObjectURL = () => { created++; return 'blob:stub-url'; };
      window.URL.revokeObjectURL = () => { revoked++; };
      window.__objectUrlCounts = () => ({ created, revoked });
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="d1"]').click();
  doc.querySelector('button[data-action="download-sbom"][data-id="d1"]').click();
  await tick(20);

  if (!capturedRequest) throw new Error('expected the sbom document endpoint to be fetched');
  assert.equal(capturedRequest.headers['Authorization'], 'Bearer test-key-123', 'download must send the API key -- a plain <a href> could not');

  const counts = dom.window.__objectUrlCounts();
  assert.equal(counts.created, 1, 'expected exactly one object URL created for the download');
  assert.equal(counts.revoked, 1, 'expected the object URL to be revoked after triggering the save');

  dom.window.close();
});

test('search filters the artifact table by ref, digest, stage, and CVE/malware id or title, case-insensitively', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const search = doc.getElementById('search-input');
  const idsShown = () => [...doc.querySelectorAll('#artifact-rows tr[data-id]')].map((tr) => tr.dataset.id);

  function type(value) {
    search.value = value;
    search.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  }

  type('ALPINE');
  assert.deepEqual(idsShown(), ['a1'], 'ref match is case-insensitive');

  type('sha256:abc123');
  assert.deepEqual(idsShown(), ['a1'], 'digest matches');

  type('openssl');
  assert.deepEqual(idsShown(), ['a1'], 'CVE finding title matches');

  type('CVE-2024-1234');
  assert.deepEqual(idsShown(), ['a1'], 'CVE finding id matches');

  type('eicar');
  assert.deepEqual(idsShown(), ['a2'], 'malware finding title matches');

  type('clamav-signature-match');
  assert.deepEqual(idsShown(), ['a2'], 'malware finding id matches');

  type('build');
  assert.deepEqual(idsShown(), ['a3'], 'current_stage matches');

  type('');
  // Rows stay sorted newest-updated-first regardless of search state:
  // a3 (11:00) > a1 (10:05) > a2 (09:30).
  assert.deepEqual(idsShown(), ['a3', 'a1', 'a2'], 'clearing the search restores every row');

  dom.window.close();
});

test('search matches maintainer team/email, and shows a distinct message when nothing matches', async () => {
  const artifactsWithMaintainer = SAMPLE_ARTIFACTS.concat([{
    id: 'a4',
    ref: 'ghcr.io/example/other:latest',
    type: 'image',
    status: 'registered',
    current_stage: '',
    stage_history: [],
    cve_findings: [],
    malware_findings: [],
    last_scan_errors: [],
    maintainer_team: 'platform-team',
    maintainer_email: 'platform@example.com',
    created_at: '2026-07-19T12:00:00Z',
    updated_at: '2026-07-19T12:00:00Z'
  }]);

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(artifactsWithMaintainer);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const search = doc.getElementById('search-input');

  function type(value) {
    search.value = value;
    search.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  }

  type('platform-team');
  assert.deepEqual(
    [...doc.querySelectorAll('#artifact-rows tr[data-id]')].map((tr) => tr.dataset.id),
    ['a4'],
    'maintainer team matches'
  );

  type('platform@example.com');
  assert.deepEqual(
    [...doc.querySelectorAll('#artifact-rows tr[data-id]')].map((tr) => tr.dataset.id),
    ['a4'],
    'maintainer email matches'
  );

  type('no-such-artifact-zzz');
  const emptyRow = doc.querySelector('#artifact-rows tr .empty');
  assert.ok(emptyRow, 'a no-match row is shown');
  // The message says "on this page" now: search only filters the page
  // the server sent, so it points at the status/type filters for
  // narrowing the whole set (see the note under the search box).
  assert.match(emptyRow.textContent, /No artifacts on this page match "no-such-artifact-zzz"/);

  dom.window.close();
});

test('search matches an artifact id, but not a finding that has since been fixed', async () => {
  const withFixed = [{
    id: 'a5',
    ref: 'alpine:3.19',
    type: 'image',
    status: 'scanned',
    current_stage: 'scan',
    stage_history: [],
    cve_findings: [
      {
        id: 'CVE-2024-5555',
        severity: 'high',
        title: 'now patched',
        source: 'trivy',
        status: 'fixed',
        first_seen_at: '2026-07-01T00:00:00Z',
        resolved_at: '2026-07-19T10:00:00Z'
      }
    ],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-19T10:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(withFixed);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const search = doc.getElementById('search-input');
  const idsShown = () => [...doc.querySelectorAll('#artifact-rows tr[data-id]')].map((tr) => tr.dataset.id);

  function type(value) {
    search.value = value;
    search.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  }

  type('a5');
  assert.deepEqual(idsShown(), ['a5'], 'searching the artifact id matches it');

  type('CVE-2024-5555');
  assert.deepEqual(idsShown(), [], 'a fixed finding must not match search -- it no longer affects this image');

  dom.window.close();
});

test('editing maintainer on the detail page POSTs to the maintainer endpoint and updates the display', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      if (url.endsWith('/a1/maintainer') && opts && opts.method === 'POST') {
        const sent = JSON.parse(opts.body);
        return jsonResponse({ ...SAMPLE_ARTIFACTS[0], maintainer_team: sent.team, maintainer_email: sent.email });
      }
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  assert.match(doc.getElementById('detail-body').innerHTML, /Not set/);

  const editBox = doc.getElementById('maintainer-edit');
  assert.equal(editBox.hidden, true, 'edit form starts hidden');
  doc.querySelector('button[data-action="edit-maintainer"]').click();
  assert.equal(editBox.hidden, false, 'Edit reveals the form');

  doc.getElementById('maintainer-edit-team').value = 'platform-security';
  doc.getElementById('maintainer-edit-email').value = 'platform-security@example.com';
  doc.querySelector('button[data-action="save-maintainer"]').click();
  await tick(20);

  const postCall = calls.find((c) => c.method === 'POST' && c.url.endsWith('/a1/maintainer'));
  assert.ok(postCall, 'expected a POST to the maintainer endpoint');
  const sentBody = JSON.parse(postCall.body);
  assert.equal(sentBody.team, 'platform-security');
  assert.equal(sentBody.email, 'platform-security@example.com');

  const bodyAfter = doc.getElementById('detail-body').innerHTML;
  assert.match(bodyAfter, /platform-security/);
  assert.match(bodyAfter, /platform-security@example\.com/);

  dom.window.close();
});

test('shows an empty-state row, not a blank table, when there are no artifacts', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.match(doc.getElementById('artifact-rows').textContent, /No artifacts yet/);
  // The register link is hidden by default (no SCM_CONFIG) -- the
  // empty state must not point at a link that isn't there.
  assert.doesNotMatch(doc.getElementById('artifact-rows').textContent, /Register one above/);
  dom.window.close();
});

test('the empty-state row points at "Register one above" only when the register link is enabled', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', allowManualRegistration: 'true' };
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.match(doc.getElementById('artifact-rows').textContent, /Register one above/);
  dom.window.close();
});

test('surfaces a visible connection error instead of silently showing nothing', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl() {
      return Promise.reject(new Error('connect ECONNREFUSED'));
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const status = doc.getElementById('status');
  assert.equal(status.className, 'error');
  assert.match(status.textContent, /Couldn't reach/);
  dom.window.close();
});

test("defaults the API base to the dashboard's own host on port 30300, not a hardcoded localhost", async () => {
  // Regression test: this dashboard originally hardcoded
  // "http://localhost:30300" as the default API address, which broke
  // the colima runtime outright (NodePorts there are only reachable via
  // the VM's own address, never "localhost") and didn't match the
  // README's port-forward-based quickstart either.
  const dom = buildDom({
    url: 'http://192.168.64.12:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const apiInput = dom.window.document.getElementById('api-base');
  assert.equal(apiInput.value, 'http://192.168.64.12:30300');
  dom.window.close();
});

test('escapes user-supplied artifact data before it reaches innerHTML', async () => {
  const malicious = [{
    id: 'a1',
    ref: '<img src=x onerror=alert(1)>',
    type: 'file',
    status: 'registered',
    current_stage: '',
    stage_history: [],
    cve_findings: [],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-19T09:00:00Z',
    updated_at: '2026-07-19T09:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(malicious);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.equal(doc.querySelectorAll('#artifact-rows img').length, 0, 'the <img> tag must not have been parsed as a real element');
  assert.match(doc.getElementById('artifact-rows').innerHTML, /&lt;img/);
  dom.window.close();
});

test('renders SARIF/other findings in their own count column and detail section', async () => {
  const withOther = [{
    id: 'a4',
    ref: '/tmp/results.sarif',
    type: 'sarif',
    status: 'scanned',
    current_stage: '',
    stage_history: [],
    cve_findings: [],
    malware_findings: [],
    other_findings: [{ id: 'no-hardcoded-secret', severity: 'high', title: 'Hardcoded secret detected', source: 'sarif' }],
    last_scan_errors: [],
    created_at: '2026-07-19T09:00:00Z',
    updated_at: '2026-07-19T09:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(statsFor({ other: 1 }));
      if (isArtifactsList(url)) return artifactsPage(withOther);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  // "With other findings" card should count this artifact.
  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  assert.equal(cardNumbers[4], '1');

  // Open the detail page and check the finding renders under its own
  // "Other" tab, not folded into the CVE tab.
  doc.querySelector('button[data-action="toggle"][data-id="a4"]').click();
  doc.querySelector('button[data-action="tab"][data-bucket="other_findings"]').click();
  const detailHtml = doc.getElementById('detail-body').innerHTML;
  assert.match(detailHtml, /Hardcoded secret detected/);

  dom.window.close();
});

test('renders misconfiguration and secret findings in their own count columns and detail sections', async () => {
  const withMisconfigAndSecret = [{
    id: 'a7',
    ref: '/tmp/results.sarif',
    type: 'sarif',
    status: 'scanned',
    current_stage: '',
    stage_history: [],
    cve_findings: [],
    malware_findings: [],
    misconfiguration_findings: [{ id: 'AVD-AWS-0001', severity: 'medium', title: 'S3 bucket is public', source: 'sarif' }],
    secret_findings: [{ id: 'aws-access-key', severity: 'critical', title: 'AWS access key committed', source: 'sarif' }],
    other_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-19T09:00:00Z',
    updated_at: '2026-07-19T09:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(statsFor({ misconfiguration: 1, secret: 1 }));
      if (isArtifactsList(url)) return artifactsPage(withMisconfigAndSecret);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  // "With misconfigurations" and "With secrets" cards -- appended after
  // the original five, at indices 5 and 6.
  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  assert.equal(cardNumbers[5], '1', 'With misconfigurations');
  assert.equal(cardNumbers[6], '1', 'With secrets');

  const row = doc.querySelector('#artifact-rows tr[data-id="a7"]');
  // Ref, Type, Status, Stage, CVEs, Malware, Misconfig, Secrets, Other
  assert.equal(row.querySelector('td:nth-child(7)').textContent.trim(), '1', 'Misconfig count column');
  assert.equal(row.querySelector('td:nth-child(8)').textContent.trim(), '1', 'Secrets count column');
  assert.equal(row.querySelector('td:nth-child(9)').textContent.trim(), '0', 'Other count column');

  doc.querySelector('button[data-action="toggle"][data-id="a7"]').click();
  doc.querySelector('button[data-action="tab"][data-bucket="misconfiguration_findings"]').click();
  assert.match(doc.getElementById('detail-body').innerHTML, /S3 bucket is public/);

  doc.querySelector('button[data-action="tab"][data-bucket="secret_findings"]').click();
  assert.match(doc.getElementById('detail-body').innerHTML, /AWS access key committed/);

  dom.window.close();
});

test('a fixed finding shows a Fixed badge, dims, and drops out of open-finding counts', async () => {
  const withFixed = [{
    id: 'a5',
    ref: 'alpine:3.19',
    type: 'image',
    status: 'scanned',
    current_stage: 'scan',
    stage_history: [],
    cve_findings: [
      {
        id: 'CVE-2024-5555',
        severity: 'high',
        title: 'now patched',
        source: 'trivy',
        status: 'fixed',
        first_seen_at: '2026-07-01T00:00:00Z',
        resolved_at: '2026-07-19T10:00:00Z'
      }
    ],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-19T10:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      // cve: 0 -- excluding fixed findings from this count is the
      // SERVER's job now (see TestStats_SuppressedFindingsDoNotCount in
      // internal/api/stats_test.go). What's still this dashboard's job,
      // and what the rest of this test checks, is the per-row column
      // and the detail page: those read the artifact's own findings
      // array and filter it client-side via openFindings.
      if (url.endsWith('/api/v1/stats')) return jsonResponse(statsFor({}));
      if (isArtifactsList(url)) return artifactsPage(withFixed);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  // "With CVEs" card must not count an artifact whose only CVE is fixed.
  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  assert.equal(cardNumbers[2], '0', 'a fixed-only CVE should not count toward "With CVEs"');

  // The table's own CVE count column must likewise read 0, not 1.
  const cveCountCell = doc.querySelector('#artifact-rows tr[data-id="a5"] td:nth-child(5)');
  assert.equal(cveCountCell.textContent.trim(), '0');

  doc.querySelector('button[data-action="toggle"][data-id="a5"]').click();
  const detailHtml = doc.getElementById('detail-body').innerHTML;
  assert.match(detailHtml, /now patched/);
  assert.match(detailHtml, /Fixed/);
  assert.match(detailHtml, /finding-fixed/);

  dom.window.close();
});

test('a VEX-suppressed finding shows a "VEX: not affected" badge, dims, and drops out of open-finding counts', async () => {
  const withSuppressed = [{
    id: 'a11',
    ref: 'alpine:3.19',
    type: 'image',
    status: 'scanned',
    current_stage: 'scan',
    stage_history: [],
    cve_findings: [
      {
        id: 'CVE-2024-6666',
        severity: 'critical',
        title: 'openssl overflow',
        source: 'trivy',
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        first_seen_at: '2026-07-01T00:00:00Z'
      }
    ],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-19T10:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      // cve: 0 for the same reason as the fixed-finding test above:
      // the card is server-computed now, the badge and the per-row
      // column below are not.
      if (url.endsWith('/api/v1/stats')) return jsonResponse(statsFor({}));
      if (isArtifactsList(url)) return artifactsPage(withSuppressed);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  // The whole point of VEX: a finding somebody has formally assessed as
  // not applying here stops inflating the numbers.
  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  assert.equal(cardNumbers[2], '0', 'a VEX-suppressed CVE should not count toward "With CVEs"');

  const cveCountCell = doc.querySelector('#artifact-rows tr[data-id="a11"] td:nth-child(5)');
  assert.equal(cveCountCell.textContent.trim(), '0');

  // ...but it stays visible on the detail page, badged and dimmed, with
  // the justification available as a tooltip.
  doc.querySelector('button[data-action="toggle"][data-id="a11"]').click();
  const detailHtml = doc.getElementById('detail-body').innerHTML;
  assert.match(detailHtml, /openssl overflow/);
  assert.match(detailHtml, /VEX: not affected/);
  assert.match(detailHtml, /finding-fixed/);
  assert.match(detailHtml, /vulnerable_code_not_in_execute_path/);
  assert.doesNotMatch(detailHtml, /badge-accent">New/, 'a suppressed finding is never "New"');

  dom.window.close();
});

test('the component box queries /api/v1/components and lists every artifact containing that purl', async () => {
  const PURL = 'pkg:apk/alpine/openssl@3.1.4-r5';
  const containing = [SAMPLE_ARTIFACTS[0], SAMPLE_ARTIFACTS[2]];
  const componentRequests = [];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components') !== -1) {
        componentRequests.push(url);
        // The endpoint answers with a bare array, not a {total,
        // artifacts} page -- see internal/api/components.go.
        return jsonResponse(url.indexOf(encodeURIComponent(PURL)) !== -1 ? containing : []);
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.equal(doc.querySelectorAll('#artifact-rows tr').length, 3, 'starts on the normal paginated list');

  const box = doc.getElementById('component-input');
  box.value = PURL;
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  assert.equal(componentRequests.length, 1, 'one request per query, not one per keystroke');
  assert.match(componentRequests[0], /\/api\/v1\/components\?purl=/);
  assert.match(componentRequests[0], new RegExp(encodeURIComponent(PURL).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    'the purl must be percent-encoded — it contains "/", "@" and often "?"');

  const ids = [...doc.querySelectorAll('#artifact-rows tr')].map((tr) => tr.dataset.id);
  assert.deepEqual(ids.sort(), ['a1', 'a3'], 'only the artifacts whose SBOM lists the component');
  assert.match(doc.getElementById('search-note').textContent, /every artifact whose SBOM lists/);
  assert.match(doc.getElementById('page-range').textContent, /2 artifacts contain this component/);
  assert.equal(doc.getElementById('page-next').disabled, true, 'a component answer is complete — nothing to page to');

  // The "Artifacts" card means "how many artifacts are there", not "how
  // many matched" -- the match count belongs in the pager line above,
  // and narrowing to 2 of 3 must not make the fleet look like it shrank.
  const artifactsCard = doc.querySelector('#cards .n').textContent;
  assert.equal(artifactsCard, '3', 'the fleet-total card must not be overwritten by the match count');

  // The component endpoint takes no status/type filter, so leaving the
  // selects live would let them display a selection that changes nothing.
  assert.equal(doc.getElementById('filter-status').disabled, true);
  assert.equal(doc.getElementById('filter-type').disabled, true);

  // The 10s poll re-renders from state: a search that only touched the
  // DOM would be wiped by the next tick, so prove it survives one.
  dom.window.document.getElementById('refresh').click();
  await tick(20);
  assert.deepEqual([...doc.querySelectorAll('#artifact-rows tr')].map((tr) => tr.dataset.id).sort(), ['a1', 'a3'],
    'the component search must survive a reload, not be a one-shot DOM filter');

  // Clearing the box (the native × on a search input fires "change")
  // returns to the normal paginated list.
  box.value = '';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);
  assert.equal(doc.querySelectorAll('#artifact-rows tr').length, 3, 'clearing returns to the full list');
  assert.match(doc.getElementById('search-note').textContent, /Search only looks at the artifacts on this page/);
  assert.equal(doc.getElementById('filter-status').disabled, false, 'the filters come back with the normal list');
  assert.equal(doc.getElementById('filter-type').disabled, false);

  dom.window.close();
});

// The two-stage flow: type what you know ("openssl"), pick from the
// packages that actually exist, land on the artifacts containing
// exactly that one.
test('typing a package name shows a picker of matching packages, and choosing one narrows to its artifacts', async () => {
  const PURL = 'pkg:apk/alpine/openssl@3.1.4-r5';
  const requests = [];
  const packages = {
    total: 2,
    packages: [
      { purl: PURL, name: 'openssl', version: '3.1.4-r5', artifacts: 2 },
      { purl: 'pkg:deb/debian/openssl@3.0.11-1', name: 'openssl', version: '3.0.11-1', artifacts: 1 }
    ]
  };

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components') !== -1) {
        requests.push(url);
        if (url.indexOf('q=') !== -1) return jsonResponse(packages);
        return jsonResponse([SAMPLE_ARTIFACTS[0], SAMPLE_ARTIFACTS[2]]);
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  const box = doc.getElementById('component-input');
  box.value = 'openssl';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  // Stage 1: packages, not artifacts.
  assert.match(requests[0], /\/api\/v1\/components\?q=openssl/);
  assert.equal(doc.getElementById('component-picker').hidden, false);
  assert.equal(doc.getElementById('artifact-table').hidden, true, 'the artifact table is the wrong answer to "which packages match?"');
  assert.equal(doc.getElementById('pager').hidden, true);

  const rows = [...doc.querySelectorAll('.pkg-row')];
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /openssl/);
  assert.match(rows[0].textContent, /3\.1\.4-r5/);
  assert.match(rows[0].textContent, /2 artifacts/);
  assert.match(rows[1].textContent, /1 artifact\b/, 'singular for one');

  // Stage 2: picking one narrows to the exact purl.
  rows[0].click();
  await tick(20);

  const exact = requests[requests.length - 1];
  assert.match(exact, /purl=/);
  assert.match(exact, new RegExp(encodeURIComponent(PURL).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.equal(doc.getElementById('component-picker').hidden, true);
  assert.equal(doc.getElementById('artifact-table').hidden, false);
  assert.deepEqual([...doc.querySelectorAll('#artifact-rows tr')].map((tr) => tr.dataset.id).sort(), ['a1', 'a3']);

  // ...and back to the matches, without retyping the search.
  const back = doc.querySelector('[data-action="back-to-matches"]');
  assert.ok(back, 'a search-derived selection must offer a way back to the other matches');
  back.click();
  await tick(20);
  assert.equal(doc.querySelectorAll('.pkg-row').length, 2, 'back returns to the picker, not to the full artifact list');

  dom.window.close();
});

// A pasted purl is an exact request and must skip the picker entirely --
// otherwise someone who already knows what they want pays for a search
// they didn't need.
test('pasting a full purl goes straight to the artifacts, skipping the picker', async () => {
  const requests = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components') !== -1) {
        requests.push(url);
        return jsonResponse([SAMPLE_ARTIFACTS[0]]);
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const box = doc.getElementById('component-input');
  box.value = 'pkg:apk/alpine/openssl@3.1.4-r5';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  assert.equal(requests.length, 1);
  assert.match(requests[0], /purl=/);
  assert.doesNotMatch(requests[0], /[?&]q=/, 'a pkg: value is an exact request, not a search');
  assert.equal(doc.getElementById('component-picker').hidden, true);
  assert.equal(doc.querySelectorAll('#artifact-rows tr').length, 1);

  dom.window.close();
});

// A capped list that looks complete is worse than no list.
test('a truncated package search says how many it is not showing', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components?q=') !== -1) {
        return jsonResponse({
          total: 4312,
          packages: [{ purl: 'pkg:golang/x/y@1.0', name: 'y', version: '1.0', artifacts: 9 }]
        });
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const box = doc.getElementById('component-input');
  box.value = 'go';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  assert.match(doc.getElementById('component-picker').textContent, /of 4312 matching packages/);

  dom.window.close();
});

test('a package search that matches nothing suggests what to try, without claiming there are no artifacts', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components?q=') !== -1) return jsonResponse({ total: 0, packages: [] });
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const box = doc.getElementById('component-input');
  box.value = 'nothing-like-this';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  const picker = doc.getElementById('component-picker').textContent;
  assert.match(picker, /No package matches/);
  assert.match(picker, /nothing-like-this/);
  assert.doesNotMatch(picker, /No artifacts yet/);

  dom.window.close();
});

test('a component search that matches nothing says so, rather than "no artifacts yet"', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components') !== -1) return jsonResponse([]);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const box = doc.getElementById('component-input');
  box.value = 'pkg:apk/alpine/nothing@1.0';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  const empty = doc.querySelector('#artifact-rows .empty').textContent;
  assert.match(empty, /No artifact/);
  assert.match(empty, /pkg:apk\/alpine\/nothing@1\.0/);
  assert.doesNotMatch(empty, /No artifacts yet/, 'there ARE artifacts — none of them ship this package');

  dom.window.close();
});

test('typing a finding name shows matching ids, and choosing one lists the artifacts still affected', async () => {
  const requests = [];
  const matches = {
    total: 2,
    findings: [
      { id: 'CVE-2021-44228', title: 'log4j RCE via JNDI', severity: 'critical', artifacts: 2 },
      { id: 'CVE-2021-45046', title: 'log4j incomplete fix', severity: 'high', artifacts: 1 }
    ]
  };

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/findings?q=') !== -1) {
        requests.push(url);
        return jsonResponse(matches);
      }
      if (url.indexOf('/api/v1/findings/') !== -1) {
        requests.push(url);
        return jsonResponse([SAMPLE_ARTIFACTS[0], SAMPLE_ARTIFACTS[2]]);
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  const box = doc.getElementById('finding-input');
  box.value = 'log4j';
  box.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  assert.match(requests[0], /\/api\/v1\/findings\?q=log4j/);
  assert.equal(doc.getElementById('artifact-table').hidden, true);
  const rows = [...doc.querySelectorAll('.pkg-row')];
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /CVE-2021-44228/);
  assert.match(rows[0].textContent, /log4j RCE via JNDI/);
  assert.match(rows[0].textContent, /critical/i, 'severity is what ranks one CVE above another');
  assert.match(rows[0].textContent, /2 artifacts/);

  rows[0].click();
  await tick(20);

  assert.match(requests[requests.length - 1], /\/api\/v1\/findings\/CVE-2021-44228\/artifacts/);
  assert.equal(doc.getElementById('artifact-table').hidden, false);
  assert.deepEqual([...doc.querySelectorAll('#artifact-rows tr')].map((tr) => tr.dataset.id).sort(), ['a1', 'a3']);
  assert.match(doc.getElementById('page-range').textContent, /2 artifacts are affected/);
  assert.match(doc.getElementById('search-note').textContent, /still affected/);
  // The fleet-total card is not the match count -- same rule the
  // component search follows.
  assert.equal(doc.querySelector('#cards .n').textContent, '3');

  doc.querySelector('[data-action="back-to-matches"]').click();
  await tick(20);
  assert.equal(doc.querySelectorAll('.pkg-row').length, 2, 'back returns to the id list');

  dom.window.close();
});

test('an exact CVE id skips the picker, and starting one search clears the other', async () => {
  const requests = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.indexOf('/api/v1/components') !== -1) {
        requests.push(url);
        return jsonResponse({ total: 1, packages: [{ purl: 'pkg:apk/alpine/openssl@3.1.4-r5', name: 'openssl', version: '3.1.4-r5', artifacts: 1 }] });
      }
      if (url.indexOf('/api/v1/findings') !== -1) {
        requests.push(url);
        return jsonResponse([SAMPLE_ARTIFACTS[0]]);
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  // A component search first...
  const componentBox = doc.getElementById('component-input');
  componentBox.value = 'openssl';
  componentBox.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);
  assert.equal(doc.querySelectorAll('.pkg-row').length, 1);

  // ...then a finding one. Two active searches would mean two sources
  // of truth for one picker area.
  const findingBox = doc.getElementById('finding-input');
  findingBox.value = 'CVE-2021-44228';
  findingBox.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  const last = requests[requests.length - 1];
  assert.match(last, /\/api\/v1\/findings\/CVE-2021-44228\/artifacts/, 'an exact id goes straight to the artifacts');
  assert.doesNotMatch(last, /[?&]q=/);
  assert.equal(componentBox.value, '', 'the other search box is cleared, not left showing a query that no longer applies');
  assert.equal(doc.getElementById('component-picker').hidden, true);
  assert.equal(doc.querySelectorAll('#artifact-rows tr').length, 1);

  dom.window.close();
});

test('an artifact registered unsafe (REQUIRE_DIGEST mismatch) shows an Unsafe badge in the row and on the detail page', async () => {
  const withUnsafe = [
    { ...SAMPLE_ARTIFACTS[0], id: 'a8', ref: 'unsafe-image:1.0', unsafe: true },
    { ...SAMPLE_ARTIFACTS[1], id: 'a9', ref: 'safe-image:1.0', unsafe: false }
  ];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(withUnsafe);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  const unsafeRow = doc.querySelector('#artifact-rows tr[data-id="a8"]');
  assert.match(unsafeRow.innerHTML, /Unsafe/, 'the row for an unsafe artifact must show the Unsafe badge');

  const safeRow = doc.querySelector('#artifact-rows tr[data-id="a9"]');
  assert.doesNotMatch(safeRow.innerHTML, /Unsafe/, 'a safely-registered artifact must not show the Unsafe badge');

  doc.querySelector('button[data-action="toggle"][data-id="a8"]').click();
  assert.match(doc.getElementById('detail-body').innerHTML, /Unsafe/, 'the detail page must also show the Unsafe badge');

  dom.window.close();
});

test('a finding first seen on the artifact\'s most recent update gets a New badge', async () => {
  const withNew = [{
    id: 'a6',
    ref: 'alpine:3.19',
    type: 'image',
    status: 'scanned',
    current_stage: 'scan',
    stage_history: [],
    cve_findings: [
      // Discovered on this very update -- first_seen_at matches updated_at.
      { id: 'CVE-2024-9001', severity: 'critical', title: 'brand new', source: 'trivy', status: 'open', first_seen_at: '2026-07-19T10:00:00Z' },
      // Been open for weeks -- must not also get flagged "New".
      { id: 'CVE-2024-1', severity: 'high', title: 'old news', source: 'trivy', status: 'open', first_seen_at: '2026-06-01T00:00:00Z' }
    ],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-06-01T00:00:00Z',
    updated_at: '2026-07-19T10:00:00Z'
  }];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(withNew);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="a6"]').click();
  const detailHtml = doc.getElementById('detail-body').innerHTML;

  const newBadgeCount = (detailHtml.match(/>New</g) || []).length;
  assert.equal(newBadgeCount, 1, 'exactly the just-discovered finding should get a New badge');
  assert.match(detailHtml, /brand new/);
  assert.match(detailHtml, /old news/);

  dom.window.close();
});

test('sends the saved API key as a Bearer Authorization header on every request', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, headers: (opts && opts.headers) || {} });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      // Set before the inline script's IIFE runs (same timing
      // guarantee buildDom already relies on for window.fetch), so the
      // very first loadAll() call picks this up as state.apiKey.
      window.localStorage.setItem('scm-api-key', 'secret123');
    }
  });

  await tick(20);

  assert.ok(calls.length > 0, 'expected at least one fetch call');
  for (const c of calls) {
    assert.equal(c.headers['Authorization'], 'Bearer secret123');
  }
  assert.equal(dom.window.document.getElementById('api-key').value, 'secret123');
  dom.window.close();
});

test('shows a distinguishable message when the API key is missing or wrong (401)', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return errorResponse(401, { error: 'missing or invalid API key' });
      return errorResponse(401, { error: 'missing or invalid API key' });
    }
  });

  await tick(20);
  const status = dom.window.document.getElementById('status');
  assert.equal(status.className, 'error');
  assert.match(status.textContent, /Unauthorized/);
  dom.window.close();
});

test('saving the form persists the API key to localStorage and re-sends it', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, headers: (opts && opts.headers) || {} });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  doc.getElementById('api-key').value = 'freshly-typed-key';
  doc.getElementById('save-api').click();
  await tick(20);

  assert.equal(dom.window.localStorage.getItem('scm-api-key'), 'freshly-typed-key');
  const last = calls[calls.length - 1];
  assert.equal(last.headers['Authorization'], 'Bearer freshly-typed-key');
  dom.window.close();
});

test('uses window.SCM_CONFIG (injected by the render-config initContainer) when nothing is saved in localStorage', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, headers: (opts && opts.headers) || {} });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      // Simulates env.js, which the initContainer writes before nginx
      // ever serves this page -- see charts/supply-chain-monitor/templates/dashboard/deployment.yaml.
      window.SCM_CONFIG = { apiBase: 'http://injected-host:30300', apiKey: 'injected-key' };
    }
  });

  await tick(20);
  const doc = dom.window.document;

  assert.equal(doc.getElementById('api-base').value, 'http://injected-host:30300');
  assert.equal(doc.getElementById('api-key').value, 'injected-key');
  assert.ok(calls.length > 0, 'expected at least one fetch call');
  for (const c of calls) {
    assert.equal(c.headers['Authorization'], 'Bearer injected-key');
    assert.equal(c.url.indexOf('http://injected-host:30300'), 0);
  }
  dom.window.close();
});

test('a value saved in localStorage still overrides window.SCM_CONFIG', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, headers: (opts && opts.headers) || {} });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.localStorage.setItem('scm-api-key', 'manually-saved-key');
      window.SCM_CONFIG = { apiBase: 'http://injected-host:30300', apiKey: 'injected-key' };
    }
  });

  await tick(20);
  const doc = dom.window.document;

  assert.equal(doc.getElementById('api-key').value, 'manually-saved-key');
  const last = calls[calls.length - 1];
  assert.equal(last.headers['Authorization'], 'Bearer manually-saved-key');
  dom.window.close();
});

test('falls back to the old manual-entry behavior when window.SCM_CONFIG is absent (e.g. env.js failed to load)', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.equal(doc.getElementById('api-key').value, '');
  assert.equal(doc.getElementById('api-base').value, 'http://localhost:30300');
  dom.window.close();
});

test('the "+ Register an artifact" link stays hidden unless allowManualRegistration is exactly "true"', async () => {
  // No SCM_CONFIG at all (env.js absent) -- must fail closed, not show
  // the link by default.
  const domNoConfig = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });
  await tick(20);
  assert.equal(domNoConfig.window.document.getElementById('register-link-section').hidden, true);
  domNoConfig.window.close();

  // Explicitly "false" -- also hidden.
  const domFalse = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', allowManualRegistration: 'false' };
    }
  });
  await tick(20);
  assert.equal(domFalse.window.document.getElementById('register-link-section').hidden, true);
  domFalse.window.close();

  // Exactly "true" -- shown.
  const domTrue = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', allowManualRegistration: 'true' };
    }
  });
  await tick(20);
  assert.equal(domTrue.window.document.getElementById('register-link-section').hidden, false);
  domTrue.window.close();
});

test('the connection settings (API/Key/Refresh/status) stay visible unless showConnectionSettings is exactly "false"', async () => {
  // No SCM_CONFIG at all (env.js absent) -- opposite default from
  // allowManualRegistration: this is a display preference, not a
  // security gate, so it must stay visible, not hide by default.
  const domNoConfig = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });
  await tick(20);
  assert.equal(domNoConfig.window.document.getElementById('conn-settings').hidden, false);
  domNoConfig.window.close();

  // Explicitly "true" -- also visible.
  const domTrue = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', showConnectionSettings: 'true' };
    }
  });
  await tick(20);
  assert.equal(domTrue.window.document.getElementById('conn-settings').hidden, false);
  domTrue.window.close();

  // Exactly "false" -- hidden.
  const domFalse = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', showConnectionSettings: 'false' };
    }
  });
  await tick(20);
  assert.equal(domFalse.window.document.getElementById('conn-settings').hidden, true);
  domFalse.window.close();
});

test('an error stays visible even with showConnectionSettings: "false" -- a broken API must not render as a quietly-empty table', async () => {
  const domIdle = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', showConnectionSettings: 'false' };
    }
  });
  await tick(20);
  // Idle "Connected to…" text is hidden along with the rest of the
  // connection settings when there's nothing wrong to report.
  assert.equal(domIdle.window.document.getElementById('status').hidden, true);
  domIdle.window.close();

  const domError = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl() {
      return Promise.reject(new Error('network down'));
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', showConnectionSettings: 'false' };
    }
  });
  await tick(20);
  const status = domError.window.document.getElementById('status');
  assert.equal(status.hidden, false, 'an error must override the hidden setting');
  assert.match(status.textContent, /Couldn't reach/);
  domError.window.close();
});

test('clicking "+ Register an artifact" opens the register modal, closing on outside click/Escape/close button and after a successful submit', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url) && opts && opts.method === 'POST') {
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.SCM_CONFIG = { apiBase: '', apiKey: '', allowManualRegistration: 'true' };
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const overlay = doc.getElementById('register-modal-overlay');
  assert.equal(overlay.hidden, true, 'starts hidden');

  doc.getElementById('register-link').click();
  assert.equal(overlay.hidden, false, 'opens on link click');

  // Inside click doesn't close it.
  doc.querySelector('#register-modal-overlay .modal-box').click();
  assert.equal(overlay.hidden, false);

  // Outside click does.
  overlay.click();
  assert.equal(overlay.hidden, true);

  // Escape closes it too.
  doc.getElementById('register-link').click();
  assert.equal(overlay.hidden, false);
  doc.dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  assert.equal(overlay.hidden, true);

  // Close button.
  doc.getElementById('register-link').click();
  assert.equal(overlay.hidden, false);
  doc.getElementById('register-modal-close').click();
  assert.equal(overlay.hidden, true);

  // A successful submit closes the modal too.
  doc.getElementById('register-link').click();
  doc.getElementById('reg-ref').value = 'alpine:3.19';
  doc.getElementById('register-form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  await tick(20);
  assert.equal(overlay.hidden, true, 'a successful registration closes the modal');

  dom.window.close();
});

test('register form POSTs the entered ref/type and reloads the list', async () => {
  const calls = [];
  let registered = false;

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url) && opts && opts.method === 'POST') {
        registered = true;
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (isArtifactsList(url)) {
        return artifactsPage(registered ? SAMPLE_ARTIFACTS.slice(0, 1) : []);
      }
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  doc.getElementById('reg-ref').value = 'ghcr.io/example/app:1.0';
  doc.getElementById('reg-type').value = 'image';
  doc.getElementById('register-form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));

  await tick(20);

  const postCall = calls.find((c) => c.method === 'POST');
  assert.ok(postCall, 'expected a POST to /api/v1/artifacts');
  const body = JSON.parse(postCall.body);
  assert.equal(body.ref, 'ghcr.io/example/app:1.0');
  assert.equal(body.type, 'image');

  const rows = doc.querySelectorAll('#artifact-rows tr[data-id]');
  assert.equal(rows.length, 1, 'list should have reloaded after registering');

  dom.window.close();
});

test('registering with maintainer team + email sends both fields and clears them on success', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url) && opts && opts.method === 'POST') {
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  doc.getElementById('reg-ref').value = 'ghcr.io/example/app:1.0';
  doc.getElementById('reg-maintainer-team').value = 'platform-security';
  doc.getElementById('reg-maintainer-email').value = 'platform-security@example.com';
  doc.getElementById('register-form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  await tick(20);

  const postCall = calls.find((c) => c.method === 'POST');
  assert.ok(postCall, 'expected a POST to /api/v1/artifacts');
  const body = JSON.parse(postCall.body);
  assert.equal(body.maintainer_team, 'platform-security');
  assert.equal(body.maintainer_email, 'platform-security@example.com');

  assert.equal(doc.getElementById('reg-maintainer-team').value, '', 'maintainer team cleared after success');
  assert.equal(doc.getElementById('reg-maintainer-email').value, '', 'maintainer email cleared after success');

  dom.window.close();
});

test('registering with only maintainer team (no email) is rejected client-side without a request', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET' });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  doc.getElementById('reg-ref').value = 'ghcr.io/example/app:1.0';
  doc.getElementById('reg-maintainer-team').value = 'platform-security';
  doc.getElementById('register-form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  await tick(20);

  assert.ok(!calls.some((c) => c.method === 'POST'), 'must not POST with only one maintainer field filled in');
  assert.match(doc.getElementById('status').textContent, /must both be filled in/);

  dom.window.close();
});

test('filling in the expected-digest field sends expected_digest and surfaces a mismatch error without clearing the form', async () => {
  const calls = [];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url) && opts && opts.method === 'POST') {
        return errorResponse(409, { error: 'resolved digest does not match the expected digest -- registration refused' });
      }
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.getElementById('reg-ref').value = 'alpine:3.19';
  doc.getElementById('reg-expected-digest').value = 'sha256:expected';
  doc.getElementById('register-form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  await tick(20);

  const postCall = calls.find((c) => c.method === 'POST');
  assert.ok(postCall, 'expected a POST to /api/v1/artifacts');
  const body = JSON.parse(postCall.body);
  assert.equal(body.expected_digest, 'sha256:expected');

  assert.match(doc.getElementById('status').textContent, /does not match the expected digest/);
  // The mismatch was rejected server-side -- the typed ref/digest stay
  // put so the user doesn't have to retype them to try again.
  assert.equal(doc.getElementById('reg-ref').value, 'alpine:3.19');

  dom.window.close();
});

test('leaving the expected-digest field blank registers normally, with no expected_digest sent', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url) && opts && opts.method === 'POST') {
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (isArtifactsList(url)) return artifactsPage([]);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  doc.getElementById('reg-ref').value = 'alpine:3.19';
  doc.getElementById('register-form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  await tick(20);

  const postCall = calls.find((c) => c.method === 'POST');
  assert.ok(postCall, 'expected a POST to /api/v1/artifacts');
  const body = JSON.parse(postCall.body);
  assert.equal('expected_digest' in body, false, 'no expected_digest key when the field is left blank');

  dom.window.close();
});

test('clicking Delete and confirming sends a DELETE request and reloads the list', async () => {
  const calls = [];
  let deleted = false;

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      const method = (opts && opts.method) || 'GET';
      calls.push({ url, method });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (method === 'DELETE' && /\/api\/v1\/artifacts\/a1$/.test(url)) {
        deleted = true;
        return jsonResponse({});
      }
      if (isArtifactsList(url)) {
        return artifactsPage(deleted ? SAMPLE_ARTIFACTS.slice(1) : SAMPLE_ARTIFACTS);
      }
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      // confirm() is a real, blocking browser dialog -- stub it to
      // drive the "user clicked OK" path deterministically.
      window.confirm = () => true;
    }
  });

  await tick(20);
  const doc = dom.window.document;
  assert.equal(doc.querySelectorAll('#artifact-rows tr[data-id]').length, 3);

  doc.querySelector('button[data-action="delete"][data-id="a1"]').click();
  await tick(20);

  const deleteCall = calls.find((c) => c.method === 'DELETE');
  assert.ok(deleteCall, 'expected a DELETE request');
  assert.match(deleteCall.url, /\/api\/v1\/artifacts\/a1$/);

  const rows = doc.querySelectorAll('#artifact-rows tr[data-id]');
  assert.equal(rows.length, 2, 'list should have reloaded without the deleted artifact');

  dom.window.close();
});

test('clicking Delete from the detail page removes the artifact and navigates back to the list', async () => {
  const calls = [];
  let deleted = false;

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      const method = (opts && opts.method) || 'GET';
      calls.push({ url, method });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (method === 'DELETE' && /\/api\/v1\/artifacts\/a1$/.test(url)) {
        deleted = true;
        return jsonResponse({});
      }
      if (isArtifactsList(url)) {
        return artifactsPage(deleted ? SAMPLE_ARTIFACTS.slice(1) : SAMPLE_ARTIFACTS);
      }
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.confirm = () => true;
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  assert.equal(doc.getElementById('detail-view').hidden, false);

  doc.querySelector('#detail-body button[data-action="delete"][data-id="a1"]').click();
  await tick(20);

  const deleteCall = calls.find((c) => c.method === 'DELETE');
  assert.ok(deleteCall, 'expected a DELETE request');

  assert.equal(dom.window.location.hash, '', 'deleting the artifact you are viewing returns to the list');
  assert.equal(doc.getElementById('detail-view').hidden, true, 'the detail page closes');
  assert.equal(doc.getElementById('list-view').hidden, false, 'the list is shown again');

  dom.window.close();
});

test('clicking Delete and cancelling the confirm dialog makes no request', async () => {
  const calls = [];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      const method = (opts && opts.method) || 'GET';
      calls.push({ url, method });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    },
    beforeParseExtra(window) {
      window.confirm = () => false;
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="delete"][data-id="a1"]').click();
  await tick(20);

  assert.ok(!calls.some((c) => c.method === 'DELETE'), 'no DELETE call should be made when the user cancels');
  assert.equal(doc.querySelectorAll('#artifact-rows tr[data-id]').length, 3, 'list unchanged');

  dom.window.close();
});

// The list endpoint is paginated server-side, so the dashboard sends
// limit/offset and drives Previous/Next off the total the server
// reports -- these two tests pin the request it actually makes, which
// is the part a stale offset or a dropped filter breaks silently.
test('Next and Previous request the neighbouring page and show the current range', async () => {
  const requested = [];
  const page = (offset) => SAMPLE_ARTIFACTS.slice(0, 1).map((a) => ({ ...a, id: 'p' + offset }));
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) {
        requested.push(url);
        const offset = Number(new URL(url, 'http://x').searchParams.get('offset'));
        // 120 artifacts total: page 1 has a next, and offset 50 has both.
        return jsonResponse({ total: 120, artifacts: page(offset) });
      }
      return errorResponse(404, { error: 'not found' });
    }
  });

  await tick(20);
  const doc = dom.window.document;

  assert.match(requested[0], /limit=50&offset=0/);
  assert.match(doc.getElementById('page-range').textContent, /1–50 of 120/);
  assert.equal(doc.getElementById('page-prev').disabled, true, 'no previous page from offset 0');
  assert.equal(doc.getElementById('page-next').disabled, false);

  doc.getElementById('page-next').click();
  await tick(20);
  assert.match(requested[requested.length - 1], /limit=50&offset=50/);
  assert.match(doc.getElementById('page-range').textContent, /51–100 of 120/);
  assert.equal(doc.getElementById('page-prev').disabled, false);

  doc.getElementById('page-prev').click();
  await tick(20);
  assert.match(requested[requested.length - 1], /limit=50&offset=0/);

  dom.window.close();
});

test('choosing a status filter sends it to the server and returns to the first page', async () => {
  const requested = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (isArtifactsList(url)) {
        requested.push(url);
        return jsonResponse({ total: 120, artifacts: SAMPLE_ARTIFACTS.slice(0, 1) });
      }
      return errorResponse(404, { error: 'not found' });
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.getElementById('page-next').click();
  await tick(20);
  assert.match(requested[requested.length - 1], /offset=50/);

  const status = doc.getElementById('filter-status');
  status.value = 'scanned';
  status.dispatchEvent(new dom.window.Event('change'));
  await tick(20);

  const last = requested[requested.length - 1];
  assert.match(last, /status=scanned/, 'the filter is applied by the server, not client-side');
  assert.match(last, /offset=0/, 'changing a filter goes back to the first page');

  // The cards stay fleet-wide while a filter narrows the table: this
  // reads SAMPLE_STATS' 3, not the filtered list's 120 or the one row
  // on screen. Same rule the component-search test asserts a few tests
  // up -- the cards answer "how much is there", which a filter doesn't
  // change, and the filtered count has the pager line to itself.
  assert.equal(doc.querySelector('#cards .n').textContent, '3',
    'the Artifacts card is the fleet total, not the filtered page count');

  dom.window.close();
});

// The "SBOM changes" section on the detail page. It loads on its own,
// after the page is already rendered, so these wait for it to fill in.
const SAMPLE_DIFF = {
  from: '2026-08-14T10:00:00Z',
  to: '2026-08-15T10:00:00Z',
  added: [{ purl: 'pkg:apk/alpine/curl@8.5.0-r0', name: 'curl', version: '8.5.0-r0' }],
  removed: [{ purl: 'pkg:apk/alpine/apk-tools@2.14.4-r0', name: 'apk-tools', version: '2.14.4-r0' }],
  version_changed: [{ purl: 'pkg:apk/alpine/openssl@3.1.4-r6', from: '3.1.4-r5', to: '3.1.4-r6' }]
};

function diffDom(diffBody) {
  return buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.includes('/components/diff')) return jsonResponse(diffBody);
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, { error: 'not found' });
    }
  });
}

test('the detail page shows SBOM changes, with upgrades separate from adds and removes', async () => {
  const dom = diffDom(SAMPLE_DIFF);
  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);

  const section = doc.getElementById('sbom-changes');
  assert.ok(section, 'no #sbom-changes section on the detail page');
  const text = section.textContent;

  // An upgrade is ONE entry under its own heading -- not an add plus a
  // remove, which is what a purl-keyed diff would show (a purl embeds
  // its version).
  assert.match(text, /Upgraded/);
  assert.match(text, /3\.1\.4-r5 → 3\.1\.4-r6/);
  assert.match(text, /Added/);
  assert.match(text, /curl/);
  assert.match(text, /Removed/);
  assert.match(text, /apk-tools/);

  dom.window.close();
});

// Two different empty states, and conflating them would mislead: an
// SBOM that genuinely didn't change vs. one that has never had two
// snapshots to compare.
test('SBOM changes distinguishes "no changes" from "not enough history"', async () => {
  const unchanged = diffDom({ from: '2026-08-14T10:00:00Z', to: '2026-08-15T10:00:00Z', added: [], removed: [], version_changed: [] });
  await tick(20);
  unchanged.window.document.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);
  assert.match(unchanged.window.document.getElementById('sbom-changes').textContent, /No component changes/);
  unchanged.window.close();

  const noHistory = diffDom({ from: null, to: null, added: [], removed: [], version_changed: [] });
  await tick(20);
  noHistory.window.document.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);
  assert.match(noHistory.window.document.getElementById('sbom-changes').textContent, /Not enough SBOM history/);
  noHistory.window.close();
});

// A failure here must stay inside the section: the rest of the detail
// page loaded fine and should not be replaced by an error.
test('a failing SBOM-changes request does not break the rest of the detail page', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.includes('/components/diff')) return errorResponse(500, { error: 'boom' });
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, { error: 'not found' });
    }
  });
  await tick(20);
  const doc = dom.window.document;
  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);

  assert.match(doc.getElementById('sbom-changes').textContent, /Could not load SBOM changes/);
  // The rest of the page is still there.
  assert.match(doc.getElementById('detail-body').textContent, /alpine:3\.19/);
  assert.equal(doc.getElementById('status').className, '', 'a section-level failure must not flag the whole page');

  dom.window.close();
});

// Licenses in the component picker. Shown only when the SBOM carried
// any -- a column of blanks on every row would be noise, since most
// packages in a real inventory have none recorded.
test('the component picker shows licenses when a package has them', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.includes('/api/v1/components?q=')) {
        return jsonResponse({
          total: 2,
          packages: [
            { purl: 'pkg:npm/bad@1.0.0', name: 'bad', version: '1.0.0', licenses: 'AGPL-3.0-only', artifacts: 3 },
            { purl: 'pkg:npm/plain@1.0.0', name: 'plain', version: '1.0.0', artifacts: 1 }
          ]
        });
      }
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, { error: 'not found' });
    }
  });
  await tick(20);
  const doc = dom.window.document;

  const input = doc.getElementById('component-input');
  input.value = 'a';
  input.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  await tick(20);

  const rows = [...doc.querySelectorAll('#component-picker .pkg-row')];
  assert.equal(rows.length, 2, 'expected both packages in the picker');
  assert.match(rows[0].textContent, /AGPL-3\.0-only/);
  // The package with no licenses gets no license cell at all.
  assert.equal(rows[1].querySelectorAll('.pkg-license').length, 0);

  dom.window.close();
});

// A 404 from the diff endpoint is ambiguous and the two meanings have
// opposite fixes, so the section has to tell them apart rather than
// showing one red error for both.
function sbomChangesText(fetchDiffImpl) {
  return buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.includes('/components/diff')) return fetchDiffImpl();
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, { error: 'not found' });
    }
  });
}

// The failure seen in a real deployment: the dashboard ships as a
// ConfigMap straight from git while the API ships as an image tag, so a
// merge can put this section in front of a binary that predates the
// endpoint. Go's ServeMux answers an unknown route with PLAIN TEXT, so
// there is no JSON error body -- that absence is what identifies it.
test('SBOM changes reports a version skew when the API has no such route', async () => {
  const dom = sbomChangesText(() => Promise.resolve({
    ok: false,
    status: 404,
    statusText: 'Not Found',
    // No JSON body -- exactly what Go's ServeMux returns.
    json: () => Promise.reject(new Error('not json'))
  }));
  await tick(20);
  const doc = dom.window.document;
  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);

  const text = doc.getElementById('sbom-changes').textContent;
  assert.match(text, /needs a newer monitor-api/);
  // Not presented as a failure of the artifact or the page.
  assert.doesNotMatch(text, /Could not load/);
  assert.equal(doc.getElementById('status').className, '');

  dom.window.close();
});

// The other 404: the endpoint exists and says the artifact does not.
test('SBOM changes reports a deleted artifact distinctly from a version skew', async () => {
  const dom = sbomChangesText(() => errorResponse(404, { error: 'artifact "a1" not found' }));
  await tick(20);
  const doc = dom.window.document;
  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);

  const text = doc.getElementById('sbom-changes').textContent;
  assert.match(text, /no longer exists/);
  assert.doesNotMatch(text, /newer monitor-api/);

  dom.window.close();
});

// Anything else still surfaces its message -- a 500 is a real problem
// and must not be dressed up as a missing feature.
test('SBOM changes still reports non-404 failures as errors', async () => {
  const dom = sbomChangesText(() => errorResponse(500, { error: 'boom' }));
  await tick(20);
  const doc = dom.window.document;
  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  await tick(20);

  const text = doc.getElementById('sbom-changes').textContent;
  assert.match(text, /Could not load SBOM changes/);
  assert.match(text, /boom/);

  dom.window.close();
});

// Scan freshness. The per-row badge is computed in the dashboard while
// the "Not scanned recently" card comes from the server's own count, so
// the two must apply the SAME rule or they contradict each other.
const NOW = Date.now();
const daysAgo = (n) => new Date(NOW - n * 24 * 60 * 60 * 1000).toISOString();

function freshnessDom(staleAfterDays, staleCount, artifacts) {
  return buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) {
        return jsonResponse(Object.assign({}, SAMPLE_STATS, {
          total: artifacts.length,
          stale_after_days: staleAfterDays,
          stale: staleCount
        }));
      }
      if (url.includes('/components/diff')) return jsonResponse({ from: null, to: null, added: [], removed: [], version_changed: [] });
      if (isArtifactsList(url)) return artifactsPage(artifacts);
      return errorResponse(404, { error: 'not found' });
    }
  });
}

const staleArtifact = Object.assign({}, SAMPLE_ARTIFACTS[0], { id: 'old', ref: 'stale:1', last_scan_at: daysAgo(30) });
const freshArtifact = Object.assign({}, SAMPLE_ARTIFACTS[0], { id: 'new', ref: 'fresh:1', last_scan_at: daysAgo(1) });
// Never scanned: last_scan_at absent entirely.
const neverScanned = Object.assign({}, SAMPLE_ARTIFACTS[0], { id: 'never', ref: 'never:1', status: 'registered' });
delete neverScanned.last_scan_at;

test('a stale artifact is badged, a fresh one is not', async () => {
  const dom = freshnessDom(7, 1, [staleArtifact, freshArtifact]);
  await tick(20);
  const doc = dom.window.document;

  const stale = doc.querySelector('#artifact-rows tr[data-id="old"]');
  const fresh = doc.querySelector('#artifact-rows tr[data-id="new"]');
  assert.match(stale.textContent, /STALE/);
  assert.doesNotMatch(fresh.textContent, /STALE/);

  // And the card, appended last so existing positional assertions hold.
  const cards = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  assert.equal(cards[cards.length - 1], '1');
  assert.match(doc.getElementById('cards').textContent, /Not scanned recently/);

  dom.window.close();
});

// The rule that keeps the badge and the server's count in agreement. In
// JS a missing date compares as older than any cutoff, so without the
// explicit guard a never-scanned artifact badges as stale while the SQL
// count excludes it — the card and the rows would contradict.
test('a never-scanned artifact is not badged stale', async () => {
  const dom = freshnessDom(7, 0, [neverScanned]);
  await tick(20);
  const doc = dom.window.document;

  const row = doc.querySelector('#artifact-rows tr[data-id="never"]');
  assert.doesNotMatch(row.textContent, /STALE/,
    'never-scanned is a different state — already swept as "registered", and excluded from the server count');

  dom.window.close();
});

// 0 means the warning is switched off, not that everything is stale.
test('freshness disabled shows no badge and no card', async () => {
  const dom = freshnessDom(0, 0, [staleArtifact]);
  await tick(20);
  const doc = dom.window.document;

  assert.doesNotMatch(doc.querySelector('#artifact-rows tr[data-id="old"]').textContent, /STALE/);
  assert.doesNotMatch(doc.getElementById('cards').textContent, /Not scanned recently/);

  dom.window.close();
});

// The 10s refresh used to close the maintainer editor out from under
// you. render() rebuilds the detail page and the editor is emitted
// hidden every pass, its open state living only in the DOM -- so a poll
// mid-edit reverted it and threw away what had been typed.
//
// Driven by capturing the real interval callback rather than waiting on
// a timer, so this asserts against the actual poll the page installs.
test('the refresh poll does not close the maintainer editor mid-edit', async () => {
  let poll;
  const artifact = Object.assign({}, SAMPLE_ARTIFACTS[0], { id: 'a1', maintainer_team: '', maintainer_email: '' });
  const dom = buildDom({
    url: 'http://localhost:30301/#/artifacts/a1',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) return jsonResponse(SAMPLE_STATS);
      if (url.includes('/components/diff')) return jsonResponse({ from: null, to: null, added: [], removed: [], version_changed: [] });
      if (isArtifactsList(url)) return artifactsPage([artifact]);
      return errorResponse(404, { error: 'not found' });
    },
    beforeParseExtra(window) {
      window.setInterval = (fn, ms) => { if (ms === 10000) poll = fn; return 0; };
    }
  });
  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('[data-action="edit-maintainer"]').click();
  const box = doc.getElementById('maintainer-edit');
  assert.equal(box.hidden, false, 'precondition: Edit opens the editor');
  doc.getElementById('maintainer-edit-team').value = 'platform';

  assert.ok(poll, 'the page must install a 10s refresh for this test to mean anything');
  poll();
  await tick(20);

  const after = doc.getElementById('maintainer-edit');
  assert.equal(after.hidden, false, 'the poll closed the editor — this is the bug');
  assert.equal(doc.getElementById('maintainer-edit-team').value, 'platform',
    'the poll discarded what had been typed');

  // And it must resume once the edit is over, or the page freezes.
  doc.querySelector('[data-action="cancel-edit-maintainer"]').click();
  let refetched = false;
  const realFetch = dom.window.fetch;
  dom.window.fetch = (u) => { refetched = true; return realFetch(u); };
  poll();
  await tick(20);
  assert.ok(refetched, 'polling must resume after Cancel');

  dom.window.close();
});

// Failed scans, fleet-wide. The per-row badge only ever showed failures
// on the page in front of you, so a few scattered through a large store
// were invisible without going looking for them.
test('failed scans get a card, and only when there are any', async () => {
  const withFailures = (n) => buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/stats')) {
        return jsonResponse(Object.assign({}, SAMPLE_STATS, {
          by_status: n ? { scanned: 2, failed: n } : { scanned: 2 }
        }));
      }
      if (url.includes('/components/diff')) return jsonResponse({ from: null, to: null, added: [], removed: [], version_changed: [] });
      if (isArtifactsList(url)) return artifactsPage(SAMPLE_ARTIFACTS);
      return errorResponse(404, { error: 'not found' });
    }
  });

  const failing = withFailures(3);
  await tick(20);
  const cards = failing.window.document.getElementById('cards');
  assert.match(cards.textContent, /Failed scans/);
  const card = cards.querySelector('.card-danger');
  assert.ok(card, 'the failure card must be visually distinct — an alarm styled like every other card is not a flag');
  assert.equal(card.querySelector('.n').textContent, '3');
  failing.window.close();

  // Zero failures: no card at all. A permanent "0 failed" is wallpaper,
  // and wallpaper is what you stop seeing before the one that matters.
  const clean = withFailures(0);
  await tick(20);
  assert.doesNotMatch(clean.window.document.getElementById('cards').textContent, /Failed scans/);
  clean.window.close();
});

// The detail page carries it too, next to the status badge.
test('the detail page badges a stale artifact', async () => {
  const dom = freshnessDom(7, 1, [staleArtifact]);
  await tick(20);
  const doc = dom.window.document;
  doc.querySelector('button[data-action="toggle"][data-id="old"]').click();
  await tick(20);

  assert.match(doc.getElementById('detail-body').textContent, /STALE/);
  dom.window.close();
});
