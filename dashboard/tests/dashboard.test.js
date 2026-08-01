'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

const SAMPLE_STAGES = { stages: ['source', 'build', 'test', 'scan', 'sign', 'publish', 'deploy'] };

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

test('renders artifact rows, summary cards, and stage pills from a live API response', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(SAMPLE_ARTIFACTS);
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

test('Details opens a modal with last-scan/digest/CVE/malware metadata, closing on an outside click but not an inside one', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(SAMPLE_ARTIFACTS);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;
  const overlay = doc.getElementById('modal-overlay');
  assert.equal(overlay.hidden, true, 'modal starts hidden');

  doc.querySelector('button[data-action="toggle"][data-id="a1"]').click();
  assert.equal(overlay.hidden, false, 'Details opens the modal');

  const body = doc.getElementById('modal-body').innerHTML;
  assert.match(body, /Last scan/);
  assert.match(body, /sha256:abc123/, 'a1 has a resolved digest');
  assert.match(body, /openssl bug/);
  assert.match(body, /Not set/, 'a1 has no maintainer configured');
  assert.match(
    body,
    /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-1234"/,
    'a real CVE id gets a Read more link to NVD'
  );

  // A click that lands inside the box must not close the modal.
  doc.querySelector('.modal-box').click();
  assert.equal(overlay.hidden, false, 'inside click leaves the modal open');

  // A click on the backdrop itself closes it.
  overlay.click();
  assert.equal(overlay.hidden, true, 'outside click closes the modal');

  // a3 has no digest and no last_scan_at (still "scanning") -- the
  // unresolved/not-yet-scanned branch of the same modal.
  doc.querySelector('button[data-action="toggle"][data-id="a3"]').click();
  const a3Body = doc.getElementById('modal-body').innerHTML;
  assert.match(a3Body, /not resolved/);
  assert.match(a3Body, /Not yet scanned/);

  // a2's only finding is malware (id "clamav-signature-match", not a
  // real CVE) -- it must not get an NVD link.
  doc.querySelector('button[data-action="toggle"][data-id="a2"]').click();
  const a2Body = doc.getElementById('modal-body').innerHTML;
  assert.doesNotMatch(a2Body, /nvd\.nist\.gov/, 'a non-CVE finding id gets no Read more link');

  dom.window.close();
});

test('the Details modal shows a download button only for documents that have actually been captured', async () => {
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(artifacts);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="d1"]').click();
  const d1Body = doc.getElementById('modal-body').innerHTML;
  assert.match(d1Body, /Download SBOM/);
  assert.match(d1Body, /Download SARIF report/);

  doc.querySelector('button[data-action="toggle"][data-id="d2"]').click();
  const d2Body = doc.getElementById('modal-body').innerHTML;
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(artifacts);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(SAMPLE_ARTIFACTS);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(artifactsWithMaintainer);
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
  assert.match(emptyRow.textContent, /No artifacts match "no-such-artifact-zzz"/);

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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(withFixed);
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

test('editing maintainer in the modal POSTs to the maintainer endpoint and updates the display', async () => {
  const calls = [];
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(SAMPLE_ARTIFACTS);
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
  assert.match(doc.getElementById('modal-body').innerHTML, /Not set/);

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

  const bodyAfter = doc.getElementById('modal-body').innerHTML;
  assert.match(bodyAfter, /platform-security/);
  assert.match(bodyAfter, /platform-security@example\.com/);

  dom.window.close();
});

test('shows an empty-state row, not a blank table, when there are no artifacts', async () => {
  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url) {
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(malicious);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(withOther);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  // "With other findings" card should count this artifact.
  const cardNumbers = [...doc.querySelectorAll('#cards .n')].map((n) => n.textContent);
  assert.equal(cardNumbers[4], '1');

  // Expand the detail row and check the finding renders there, not
  // folded into the CVE column/section.
  doc.querySelector('button[data-action="toggle"][data-id="a4"]').click();
  const detailHtml = doc.getElementById('modal-body').innerHTML;
  assert.match(detailHtml, /Hardcoded secret detected/);
  assert.match(detailHtml, /Other findings/);

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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(withMisconfigAndSecret);
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
  const detailHtml = doc.getElementById('modal-body').innerHTML;
  assert.match(detailHtml, /S3 bucket is public/);
  assert.match(detailHtml, /Misconfiguration findings/);
  assert.match(detailHtml, /AWS access key committed/);
  assert.match(detailHtml, /Secret findings/);

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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(withFixed);
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
  const detailHtml = doc.getElementById('modal-body').innerHTML;
  assert.match(detailHtml, /now patched/);
  assert.match(detailHtml, /Fixed/);
  assert.match(detailHtml, /finding-fixed/);

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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(withNew);
      return errorResponse(404, {});
    }
  });

  await tick(20);
  const doc = dom.window.document;

  doc.querySelector('button[data-action="toggle"][data-id="a6"]').click();
  const detailHtml = doc.getElementById('modal-body').innerHTML;

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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts') && opts && opts.method === 'POST') {
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts') && opts && opts.method === 'POST') {
        registered = true;
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (url.endsWith('/api/v1/artifacts')) {
        return jsonResponse(registered ? SAMPLE_ARTIFACTS.slice(0, 1) : []);
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
      if (url.endsWith('/api/v1/artifacts') && opts && opts.method === 'POST') {
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts') && opts && opts.method === 'POST') {
        return errorResponse(409, { error: 'resolved digest does not match the expected digest -- registration refused' });
      }
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (url.endsWith('/api/v1/artifacts') && opts && opts.method === 'POST') {
        return jsonResponse({ id: 'new1', ...JSON.parse(opts.body) });
      }
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse([]);
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
      if (method === 'DELETE' && /\/api\/v1\/artifacts\/a1$/.test(url)) {
        deleted = true;
        return jsonResponse({});
      }
      if (url.endsWith('/api/v1/artifacts')) {
        return jsonResponse(deleted ? SAMPLE_ARTIFACTS.slice(1) : SAMPLE_ARTIFACTS);
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

test('clicking Delete and cancelling the confirm dialog makes no request', async () => {
  const calls = [];

  const dom = buildDom({
    url: 'http://localhost:30301/',
    fetchImpl(url, opts) {
      const method = (opts && opts.method) || 'GET';
      calls.push({ url, method });
      if (url.endsWith('/api/v1/pipeline/stages')) return jsonResponse(SAMPLE_STAGES);
      if (url.endsWith('/api/v1/artifacts')) return jsonResponse(SAMPLE_ARTIFACTS);
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
