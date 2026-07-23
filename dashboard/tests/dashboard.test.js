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
    stage_history: [
      { stage: 'build', timestamp: '2026-07-19T10:00:00Z', note: 'CI job #1' },
      { stage: 'scan', timestamp: '2026-07-19T10:05:00Z' }
    ],
    cve_findings: [{ id: 'CVE-2024-1234', severity: 'high', title: 'openssl bug', source: 'trivy' }],
    malware_findings: [],
    last_scan_errors: [],
    created_at: '2026-07-19T09:00:00Z',
    updated_at: '2026-07-19T10:05:00Z'
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

function tick(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildDom({ url, fetchImpl, beforeParseExtra }) {
  return new JSDOM(html, {
    url,
    runScripts: 'dangerously',
    resources: 'usable',
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
  const detailHtml = doc.querySelector('tr.detail-row').innerHTML;
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
  const detailHtml = doc.querySelector('tr.detail-row').innerHTML;
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
  const detailHtml = doc.querySelector('tr.detail-row').innerHTML;
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
  const detailHtml = doc.querySelector('tr.detail-row').innerHTML;

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
