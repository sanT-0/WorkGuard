/*
 * WorkGuard administration console.
 *
 * This file is intentionally dependency-free.  Every value coming from the API
 * is inserted with textContent / DOM nodes, never with innerHTML, so policy
 * names, event details, audit records, and device names cannot inject markup.
 */

'use strict';

const API = '/api/v1';

const state = {
  authMode: 'dev',
  user: 'dev-admin',
  role: 'security_admin',
  token: '',
  staleAfterSeconds: 1800,
  devices: [],
  policies: [],
  events: [],
  audit: [],
  exceptions: [],
  selectedPolicyId: null,
  countdownTimer: null,
};

class ApiError extends Error {
  constructor(status, message, payload) {
    super(message);
    this.status = status;
    this.payload = payload;
  }
}

/* ------------------------------------------------------------------ helpers */

function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'onclick') node.addEventListener('click', value);
      else node.setAttribute(key, String(value));
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function badge(status) {
  const value = String(status || 'unknown');
  return h('span', { class: `badge badge-${value.replace(/[^a-z_]/g, '')}` }, value.replace(/_/g, ' '));
}

function formatRelative(iso) {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return String(iso);
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 0) return 'in the future';
  if (seconds < 15) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function formatTimestamp(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? String(iso) : date.toLocaleString();
}

function shortId(value, length = 8) {
  return value ? String(value).slice(0, length) : '—';
}

function errorText(error) {
  if (error instanceof ApiError) {
    const requestId = error.payload && error.payload.error && error.payload.error.request_id;
    return requestId ? `${error.message} (request ${requestId})` : error.message;
  }
  return error && error.message ? error.message : String(error);
}

function showMessage(kind, text) {
  const banner = document.getElementById('message-banner');
  if (!banner) return;
  banner.className = `banner banner-${kind}`;
  document.getElementById('message-icon').textContent =
    kind === 'error' ? '⚠️' : kind === 'success' ? '✅' : 'ℹ️';
  document.getElementById('message-text').textContent = text;
  banner.hidden = false;
}

function hideMessage() {
  const banner = document.getElementById('message-banner');
  if (banner) banner.hidden = true;
}

/* --------------------------------------------------------------------- API */

async function api(path, options = {}) {
  const { method = 'GET', body, asUser, asRole } = options;
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  if (state.authMode === 'dev') {
    headers['X-Dev-User'] = asUser || state.user;
    headers['X-Dev-Role'] = asRole || state.role;
  } else if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  let response;
  try {
    response = await fetch(API + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
    });
  } catch (error) {
    throw new ApiError(0, `Network error: ${error.message}`);
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { raw: text };
    }
  }

  if (!response.ok) {
    const message =
      (payload && payload.error && payload.error.message) ||
      (payload && typeof payload.detail === 'string' && payload.detail) ||
      `Request failed with HTTP ${response.status}`;
    throw new ApiError(response.status, message, payload);
  }
  return payload;
}

/* ---------------------------------------------------------------- identity */

function loadIdentity() {
  state.user = sessionStorage.getItem('wg.dev.user') || 'dev-admin';
  state.role = sessionStorage.getItem('wg.dev.role') || 'security_admin';
  state.token = sessionStorage.getItem('wg.oidc.token') || '';
}

function saveIdentity() {
  sessionStorage.setItem('wg.dev.user', state.user);
  sessionStorage.setItem('wg.dev.role', state.role);
  sessionStorage.setItem('wg.oidc.token', state.token);
}

function renderIdentity() {
  const devBox = document.getElementById('dev-identity');
  const oidcBox = document.getElementById('oidc-identity');
  devBox.hidden = state.authMode !== 'dev';
  oidcBox.hidden = state.authMode === 'dev';
  document.getElementById('dev-user').value = state.user;
  document.getElementById('dev-role').value = state.role;
  document.getElementById('oidc-token').value = state.token;
}

/* ------------------------------------------------------------------ render */

function switchTab(tab) {
  const tabs = ['overview', 'devices', 'policies', 'enrollment', 'events', 'audit', 'exceptions'];
  tabs.forEach((name) => {
    const view = document.getElementById(`view-${name}`);
    if (view) view.hidden = name !== tab;
  });
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.dataset.tab === tab);
  });
  const titles = {
    overview: 'Fleet Overview',
    devices: 'Managed Endpoint Inventory',
    policies: 'Policy Studio',
    enrollment: 'Device Enrollment',
    events: 'Security Events',
    audit: 'Audit Trail',
    exceptions: 'Scoped Exceptions',
  };
  document.getElementById('page-title').textContent = titles[tab] || 'WorkGuard';
  if (tab === 'exceptions') populateExceptionDevices();
}

function renderOverview() {
  const counts = state.devices.reduce(
    (acc, device) => {
      acc.total += 1;
      if (device.status === 'compliant') acc.compliant += 1;
      if (device.status === 'noncompliant') acc.noncompliant += 1;
      if (device.status === 'stale') acc.stale += 1;
      return acc;
    },
    { total: 0, compliant: 0, noncompliant: 0, stale: 0 }
  );

  document.getElementById('stat-total').textContent = String(counts.total);
  document.getElementById('stat-compliant').textContent = String(counts.compliant);
  document.getElementById('stat-noncompliant').textContent = String(counts.noncompliant);
  document.getElementById('stat-stale').textContent = String(counts.stale);
  document.getElementById('stat-total-sub').textContent =
    `${state.devices.filter((d) => d.status !== 'revoked').length} active, ${state.devices.filter((d) => d.status === 'revoked').length} revoked`;
  document.getElementById('stat-stale-sub').textContent =
    `No heartbeat for ${Math.round(state.staleAfterSeconds / 60)} minutes`;

  const body = document.getElementById('recent-events-body');
  clear(body);
  const recent = state.events.slice(0, 6);
  if (recent.length === 0) {
    body.append(h('tr', null, h('td', { colspan: '6', class: 'empty' }, 'No events recorded yet.')));
    return;
  }
  for (const event of recent) {
    body.append(
      h(
        'tr',
        null,
        h('td', null, h('code', { class: 'code-inline' }, event.event_type)),
        h('td', null, badge(event.severity)),
        h('td', null, event.source),
        h('td', null, h('strong', null, event.response_state)),
        h('td', { class: 'mono' }, event.device_id ? shortId(event.device_id) : 'central'),
        h('td', { title: formatTimestamp(event.occurred_at) }, formatRelative(event.occurred_at))
      )
    );
  }
}

function filteredDevices() {
  const query = (document.getElementById('device-search').value || '').trim().toLowerCase();
  if (!query) return state.devices;
  return state.devices.filter((device) =>
    [device.display_name, device.os_edition, device.os_version, device.id, device.assigned_user_id]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query))
  );
}

function renderDevices() {
  const body = document.getElementById('devices-body');
  clear(body);
  const devices = filteredDevices();
  if (devices.length === 0) {
    body.append(h('tr', null, h('td', { colspan: '6', class: 'empty' }, 'No matching devices.')));
    return;
  }

  for (const device of devices) {
    const actions = h('div', { class: 'row-actions' });
    actions.append(
      h('button', { class: 'btn btn-secondary btn-sm', 'data-action': 'inspect-device', 'data-id': device.id }, 'Inspect')
    );
    if (device.status !== 'revoked') {
      actions.append(
        h('button', { class: 'btn btn-secondary btn-sm', 'data-action': 'rotate-device', 'data-id': device.id }, 'Rotate token'),
        h('button', { class: 'btn btn-danger btn-sm', 'data-action': 'revoke-device', 'data-id': device.id }, 'Revoke')
      );
    }

    body.append(
      h(
        'tr',
        null,
        h(
          'td',
          null,
          h('div', { style: 'font-weight:700;' }, device.display_name),
          h('div', { class: 'mono' }, device.id)
        ),
        h(
          'td',
          null,
          h('div', null, device.os_edition),
          h('div', { class: 'mono' }, device.os_version)
        ),
        h('td', null, badge(device.status)),
        h('td', { title: formatTimestamp(device.last_seen_at) }, h('span', { class: 'freshness-chip' }, formatRelative(device.last_seen_at))),
        h(
          'td',
          { class: 'mono' },
          `v${device.policy_version_observed ?? '—'} / v${device.policy_version_desired ?? '—'}`
        ),
        h('td', null, actions)
      )
    );
  }
}

function policyActions(policy) {
  const actions = h('div', { class: 'row-actions' });
  actions.append(
    h('button', { class: 'btn btn-secondary btn-sm', 'data-action': 'view-policy', 'data-id': policy.id }, 'View')
  );
  switch (policy.lifecycle_state) {
    case 'draft':
      actions.append(
        h('button', { class: 'btn btn-secondary btn-sm', 'data-action': 'edit-policy', 'data-id': policy.id }, 'Edit'),
        h('button', { class: 'btn btn-primary btn-sm', 'data-action': 'submit-policy', 'data-id': policy.id }, 'Submit')
      );
      break;
    case 'submitted':
      actions.append(
        h('button', { class: 'btn btn-primary btn-sm', 'data-action': 'approve-policy', 'data-id': policy.id }, 'Approve')
      );
      break;
    case 'approved':
      actions.append(
        h('button', { class: 'btn btn-primary btn-sm', 'data-action': 'publish-policy', 'data-id': policy.id }, 'Publish')
      );
      break;
    case 'published':
      actions.append(
        h('button', { class: 'btn btn-secondary btn-sm', 'data-action': 'new-draft', 'data-id': policy.id }, 'New draft'),
        h('button', { class: 'btn btn-danger btn-sm', 'data-action': 'rollback-policy', 'data-id': policy.id }, 'Rollback')
      );
      break;
    default:
      break;
  }
  return actions;
}

function renderPolicies() {
  const body = document.getElementById('policies-body');
  clear(body);
  if (state.policies.length === 0) {
    body.append(h('tr', null, h('td', { colspan: '6', class: 'empty' }, 'No policies. Create one to get started.')));
    return;
  }
  for (const policy of state.policies) {
    body.append(
      h(
        'tr',
        null,
        h(
          'td',
          null,
          h('div', { style: 'font-weight:700;' }, policy.name),
          h('div', { class: 'mono' }, policy.id)
        ),
        h('td', null, badge(policy.lifecycle_state)),
        h('td', null, policy.version ? `v${policy.version}` : '—'),
        h('td', { title: formatTimestamp(policy.updated_at) }, formatRelative(policy.updated_at)),
        h('td', { class: 'mono' }, policy.created_by || '—'),
        h('td', null, policyActions(policy))
      )
    );
  }
}

function renderEvents() {
  const body = document.getElementById('events-body');
  clear(body);
  if (state.events.length === 0) {
    body.append(h('tr', null, h('td', { colspan: '6', class: 'empty' }, 'No events recorded.')));
    return;
  }
  for (const event of state.events) {
    body.append(
      h(
        'tr',
        null,
        h('td', null, h('code', { class: 'code-inline' }, event.event_type)),
        h('td', null, badge(event.severity)),
        h('td', null, event.source),
        h('td', null, event.response_state),
        h('td', { class: 'mono' }, event.device_id || 'system'),
        h('td', { title: formatTimestamp(event.occurred_at) }, formatRelative(event.occurred_at))
      )
    );
  }
}

function renderAudit() {
  const body = document.getElementById('audit-body');
  clear(body);
  if (state.audit.length === 0) {
    body.append(h('tr', null, h('td', { colspan: '5', class: 'empty' }, 'No audit records.')));
    return;
  }
  for (const entry of state.audit) {
    body.append(
      h(
        'tr',
        null,
        h('td', null, h('code', { class: 'code-inline' }, entry.action)),
        h('td', { class: 'mono' }, entry.actor_user_id),
        h(
          'td',
          null,
          h('div', null, entry.target_type),
          h('div', { class: 'mono' }, entry.target_id || '—')
        ),
        h('td', { class: 'mono' }, JSON.stringify(entry.details || {})),
        h('td', { title: formatTimestamp(entry.created_at) }, formatRelative(entry.created_at))
      )
    );
  }
}

function renderExceptions() {
  const body = document.getElementById('exceptions-body');
  clear(body);
  if (state.exceptions.length === 0) {
    body.append(h('tr', null, h('td', { colspan: '6', class: 'empty' }, 'No exceptions recorded.')));
    return;
  }
  for (const item of state.exceptions) {
    const actions = h('div', { class: 'row-actions' });
    if (item.status === 'active') {
      actions.append(
        h('button', { class: 'btn btn-danger btn-sm', 'data-action': 'revoke-exception', 'data-id': item.id }, 'Revoke')
      );
    }
    body.append(
      h(
        'tr',
        null,
        h('td', { class: 'mono' }, item.device_id),
        h('td', { class: 'mono' }, item.control_id),
        h('td', null, item.reason),
        h('td', null, badge(item.status)),
        h('td', { title: formatTimestamp(item.expires_at) }, formatTimestamp(item.expires_at)),
        h('td', null, actions)
      )
    );
  }
}

/* --------------------------------------------------------------- refreshing */

async function refreshAll() {
  const requests = [
    api('/admin/devices?limit=200'),
    api('/admin/policies'),
    api('/admin/events?limit=100'),
    api('/admin/audit-events?limit=100'),
    api('/admin/exceptions?limit=100'),
  ];
  const results = await Promise.allSettled(requests);

  if (results[0].status === 'fulfilled') state.devices = results[0].value.items || [];
  if (results[1].status === 'fulfilled') state.policies = results[1].value.items || [];
  if (results[2].status === 'fulfilled') state.events = results[2].value.items || [];
  if (results[3].status === 'fulfilled') state.audit = results[3].value.items || [];
  if (results[4].status === 'fulfilled') state.exceptions = results[4].value.items || [];

  const failure = results.find((result) => result.status === 'rejected');
  if (failure) showMessage('error', errorText(failure.reason));

  renderOverview();
  renderDevices();
  renderPolicies();
  renderEvents();
  renderAudit();
  renderExceptions();
  if (!document.getElementById('view-exceptions').hidden) {
    await populateExceptionDevices();
  }

  if (state.selectedPolicyId) {
    try {
      await loadPolicyDetail(state.selectedPolicyId);
    } catch (error) {
      showMessage('error', errorText(error));
    }
  }
}

/* -------------------------------------------------------------- devices UI */

async function openDeviceModal(deviceId) {
  const device = await api(`/admin/devices/${encodeURIComponent(deviceId)}`);
  const controls = device.controls || [];
  const details = device.compliance_details || [];
  const excepted = details.filter((item) => item.status === 'excepted');
  const missing = details.filter((item) => item.status !== 'excepted');

  const body = h('div');
  body.append(
    h(
      'div',
      { class: 'kv-grid' },
      kv('Status', badge(device.status)),
      kv('Operating system', `${device.os_edition} — ${device.os_version}`),
      kv('Assigned user', device.assigned_user_id || '—'),
      kv('Agent version', device.agent_version || '—'),
      kv('Last seen', `${formatRelative(device.last_seen_at)} (${formatTimestamp(device.last_seen_at)})`),
      kv('Assigned policy', device.assigned_policy_id || '—')
    )
  );

  body.append(h('h3', { style: 'font-size:14px; margin:18px 0 10px;' }, 'Control read-back'));
  if (controls.length === 0) {
    body.append(h('div', { class: 'notice' }, 'No control results have been submitted for this device.'));
  } else {
    const table = h('table', null, h('thead', null, h('tr', null,
      h('th', null, 'Control'), h('th', null, 'Status'), h('th', null, 'Provider'), h('th', null, 'Observed'), h('th', null, 'Detail'))));
    const tbody = h('tbody');
    for (const control of controls) {
      tbody.append(
        h('tr', null,
          h('td', null, h('code', { class: 'code-inline' }, control.control_id)),
          h('td', null, badge(control.status)),
          h('td', null, control.provider || '—'),
          h('td', { title: formatTimestamp(control.observed_at) }, formatRelative(control.observed_at)),
          h('td', { class: 'mono' }, control.error_code || control.safe_details || '—')
        )
      );
    }
    table.append(tbody);
    body.append(h('div', { class: 'table-scroll' }, table));
  }

  if (missing.length > 0) {
    body.append(
      h('div', { class: 'notice', style: 'margin-top:14px; border-color: rgba(239,68,68,0.35);' },
        `Required controls not enforced: ${missing.map((item) => `${item.control_id} (${item.status})`).join(', ')}`)
    );
  }
  if (excepted.length > 0) {
    body.append(
      h('div', { class: 'notice', style: 'margin-top:14px;' },
        `Covered by active exceptions: ${excepted.map((item) => `${item.control_id} (expires ${formatTimestamp(item.expires_at)})`).join(', ')}`)
    );
  }

  const footer = [];
  if (device.status !== 'revoked') {
    footer.push(h('button', { class: 'btn btn-secondary', 'data-action': 'rotate-device', 'data-id': device.id }, 'Rotate credential'));
    footer.push(h('button', { class: 'btn btn-danger', 'data-action': 'revoke-device', 'data-id': device.id }, 'Revoke device'));
  }
  footer.push(h('button', { class: 'btn btn-secondary', 'data-action': 'close-modal' }, 'Close'));

  openModal({
    title: device.display_name,
    desc: device.id,
    body,
    footer,
  });
}

function kv(label, value) {
  return h('div', { class: 'kv' }, h('div', { class: 'kv-label' }, label), h('div', { class: 'kv-val' }, value));
}

async function rotateDevice(deviceId) {
  if (!window.confirm('Rotate this device credential? The old token stops working immediately.')) return;
  const result = await api(`/admin/devices/${encodeURIComponent(deviceId)}/rotate-credential`, { method: 'POST' });
  const body = h('div');
  body.append(
    h('div', { class: 'notice' }, 'Copy this token into the endpoint now. It is shown once and is not stored in plaintext by the server.'),
    h('div', { class: 'code-box', id: 'rotated-token' }, result.device_token)
  );
  openModal({
    title: 'New device credential',
    desc: `${result.device_id} — issued ${formatTimestamp(result.issued_at)}`,
    body,
    footer: [
      h('button', { class: 'btn btn-secondary', 'data-action': 'copy-rotated-token' }, 'Copy token'),
      h('button', { class: 'btn btn-primary', 'data-action': 'close-modal' }, 'Done'),
    ],
  });
  await refreshAll();
}

async function revokeDevice(deviceId) {
  const reason = window.prompt('Reason for revoking this device (recorded in the audit log):', '');
  if (!reason || reason.trim().length < 3) return;
  await api(`/admin/devices/${encodeURIComponent(deviceId)}/revoke`, {
    method: 'POST',
    body: { reason: reason.trim() },
  });
  closeModal();
  showMessage('success', 'Device revoked. Its credential can no longer authenticate.');
  await refreshAll();
}

/* -------------------------------------------------------------- policies UI */

async function loadPolicyDetail(policyId) {
  const detail = await api(`/admin/policies/${encodeURIComponent(policyId)}`);
  state.selectedPolicyId = policyId;

  document.getElementById('policy-detail-card').hidden = false;
  document.getElementById('policy-detail-title').textContent = detail.name;
  document.getElementById('policy-detail-json').textContent = JSON.stringify(detail.policy, null, 2);

  const meta = document.getElementById('policy-detail-meta');
  clear(meta);
  meta.append(
    kv('Lifecycle', badge(detail.lifecycle_state)),
    kv('Published version', detail.version ? `v${detail.version}` : '—'),
    kv('Policy ID', h('span', { class: 'mono' }, detail.id)),
    kv('Created by', detail.created_by || '—'),
    kv('Approved by', detail.approved_by || '—'),
    kv('Published by', detail.published_by || '—')
  );

  const versionsBody = document.getElementById('policy-versions-body');
  clear(versionsBody);
  for (const version of detail.versions || []) {
    versionsBody.append(
      h('tr', null,
        h('td', null, h('strong', null, `v${version.version}`)),
        h('td', { class: 'mono', title: version.digest_sha256 }, shortId(version.digest_sha256, 24)),
        h('td', { class: 'mono' }, version.key_id || '—'),
        h('td', null, version.rollback_of_version ? `v${version.rollback_of_version}` : '—'),
        h('td', { class: 'mono' }, version.published_by || '—'),
        h('td', { title: formatTimestamp(version.published_at) }, formatRelative(version.published_at)),
        h('td', null, version.reason || '—')
      )
    );
  }
}

function jsonField(label, value) {
  const textarea = h('textarea', { class: 'textarea', spellcheck: 'false' });
  textarea.value = JSON.stringify(value, null, 2);
  return h('div', { class: 'field' }, h('label', null, label), textarea);
}

async function createPolicyModal() {
  let template = {
    schema_version: '1.0.0',
    policy_id: '00000000-0000-4000-8000-000000000000',
    policy_version: 1,
    name: 'New policy',
    description: '',
    rollout_mode: 'enforce',
    controls: [
      {
        control_id: 'removable_storage',
        required: true,
        settings: { action: 'deny', device_classes: ['USB_MSD'], audit_only: false },
      },
    ],
  };
  if (state.policies.length > 0) {
    try {
      const detail = await api(`/admin/policies/${encodeURIComponent(state.policies[0].id)}`);
      template = JSON.parse(JSON.stringify(detail.policy));
      template.policy_id = '00000000-0000-4000-8000-000000000000';
      template.policy_version = 1;
      template.name = '';
    } catch {
      /* fall back to the minimal template */
    }
  }

  const nameInput = h('input', { class: 'input', type: 'text', maxlength: '120', placeholder: 'Policy name' });
  const reasonInput = h('input', { class: 'input', type: 'text', maxlength: '500', placeholder: 'Why is this policy being created?' });
  const policyArea = jsonField('Policy JSON (validated against policy.schema.json)', template);

  const body = h('div');
  body.append(
    h('div', { class: 'field' }, h('label', null, 'Name'), nameInput),
    h('div', { class: 'field' }, h('label', null, 'Reason'), reasonInput),
    policyArea,
    h('div', { class: 'field-hint' }, 'The server assigns the policy ID and starts at version 1 as a draft. Invalid control settings are rejected.')
  );

  openModal({
    title: 'Create draft policy',
    desc: 'A draft is editable and cannot be served to devices until it is submitted, approved, and published.',
    body,
    footer: [
      h('button', { class: 'btn btn-secondary', 'data-action': 'close-modal' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', 'data-action': 'submit-create-policy' }, 'Create draft'),
    ],
  });

  state.modalForm = { nameInput, reasonInput, policyArea };
}

async function submitCreatePolicy(button) {
  const { nameInput, reasonInput, policyArea } = state.modalForm || {};
  if (!nameInput || !reasonInput || !policyArea) return;
  const name = nameInput.value.trim();
  const reason = reasonInput.value.trim();
  if (!name || reason.length < 3) {
    showMessage('error', 'A name and a reason of at least 3 characters are required.');
    return;
  }

  let policy;
  try {
    policy = JSON.parse(policyArea.querySelector('textarea').value);
  } catch (error) {
    showMessage('error', `Policy JSON is invalid: ${error.message}`);
    return;
  }
  policy.name = name;

  await runButton(button, async () => {
    const created = await api('/admin/policies', { method: 'POST', body: { name, policy, reason } });
    closeModal();
    showMessage('success', `Draft "${created.name}" created.`);
    await refreshAll();
    await loadPolicyDetail(created.id);
    switchTab('policies');
  });
}

async function editPolicyModal(policyId) {
  const detail = await api(`/admin/policies/${encodeURIComponent(policyId)}`);
  const reasonInput = h('input', { class: 'input', type: 'text', maxlength: '500', placeholder: 'Describe the change' });
  const area = jsonField('Draft policy JSON', detail.policy);

  const body = h('div');
  body.append(
    h('div', { class: 'notice' }, 'Only drafts are editable. The server re-validates the JSON Schema and keeps the same draft version.'),
    h('div', { class: 'field' }, h('label', null, 'Reason'), reasonInput),
    area
  );

  openModal({
    title: `Edit ${detail.name}`,
    desc: `Draft version ${(detail.versions[0] || {}).version || '—'}`,
    body,
    footer: [
      h('button', { class: 'btn btn-secondary', 'data-action': 'close-modal' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', 'data-action': 'submit-edit-policy', 'data-id': policyId }, 'Save draft'),
    ],
  });
  state.modalForm = { reasonInput, area };
}

async function submitEditPolicy(button, policyId) {
  const { reasonInput, area } = state.modalForm || {};
  if (!reasonInput || !area) return;
  const reason = reasonInput.value.trim();
  if (reason.length < 3) {
    showMessage('error', 'A reason of at least 3 characters is required.');
    return;
  }
  let policy;
  try {
    policy = JSON.parse(area.querySelector('textarea').value);
  } catch (error) {
    showMessage('error', `Policy JSON is invalid: ${error.message}`);
    return;
  }

  await runButton(button, async () => {
    await api(`/admin/policies/${encodeURIComponent(policyId)}`, {
      method: 'PATCH',
      body: { policy, reason },
    });
    closeModal();
    showMessage('success', 'Draft updated.');
    await refreshAll();
    await loadPolicyDetail(policyId);
  });
}

async function submitPolicy(policyId) {
  if (!window.confirm('Submit this draft for independent approval?')) return;
  await api(`/admin/policies/${encodeURIComponent(policyId)}/submit`, { method: 'POST' });
  showMessage('success', 'Draft submitted. A different administrator must approve it.');
  await refreshAll();
}

async function approvePolicyModal(policyId) {
  const detail = await api(`/admin/policies/${encodeURIComponent(policyId)}`);
  const notes = h('input', { class: 'input', type: 'text', maxlength: '500', placeholder: 'Approval notes' });
  const body = h('div');
  body.append(
    h('div', { class: 'notice' },
      `Author: ${detail.created_by || 'unknown'}. The server rejects approval by the author. In OIDC mode your token identity is used.`),
    h('div', { class: 'field' }, h('label', null, 'Approval notes'), notes)
  );

  let approverInput = null;
  if (state.authMode === 'dev') {
    approverInput = h('input', { class: 'input', type: 'text', maxlength: '120', placeholder: 'Approver user id (must differ from author)' });
    body.append(
      h('div', { class: 'field' }, h('label', null, 'Approver identity (development auth only)'), approverInput)
    );
  }

  openModal({
    title: `Approve ${detail.name}`,
    desc: 'Approval is a state transition, not a signature. Signing happens per device when the policy is fetched.',
    body,
    footer: [
      h('button', { class: 'btn btn-secondary', 'data-action': 'close-modal' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', 'data-action': 'submit-approve-policy', 'data-id': policyId }, 'Approve'),
    ],
  });
  state.modalForm = { notes, approverInput };
}

async function submitApprovePolicy(button, policyId) {
  const { notes, approverInput } = state.modalForm || {};
  if (!notes) return;
  if (notes.value.trim().length < 3) {
    showMessage('error', 'Approval notes of at least 3 characters are required.');
    return;
  }
  const asUser = approverInput ? approverInput.value.trim() : undefined;
  if (state.authMode === 'dev' && !asUser) {
    showMessage('error', 'Enter the approver identity. Development auth trusts this header; use a real OIDC token outside local development.');
    return;
  }

  await runButton(button, async () => {
    await api(`/admin/policies/${encodeURIComponent(policyId)}/approve`, {
      method: 'POST',
      body: { approval_notes: notes.value.trim() },
      asUser,
    });
    closeModal();
    showMessage('success', 'Policy approved. It can now be published by a non-author administrator.');
    await refreshAll();
    await loadPolicyDetail(policyId);
  });
}

async function publishPolicyModal(policyId) {
  const detail = await api(`/admin/policies/${encodeURIComponent(policyId)}`);
  const latest = (detail.versions || [])[0];
  const reason = h('input', { class: 'input', type: 'text', maxlength: '500', placeholder: 'Release reason' });
  const body = h('div');
  body.append(
    h('div', { class: 'notice' },
      `Publishing immutable version v${latest ? latest.version : '—'} to all non-revoked devices. The stored digest is ${shortId(latest && latest.digest_sha256, 24)}.`),
    h('div', { class: 'field' }, h('label', null, 'Reason'), reason)
  );

  openModal({
    title: `Publish ${detail.name}`,
    desc: 'Publication does not embed a reusable signature; each device receives a short-lived signed envelope.',
    body,
    footer: [
      h('button', { class: 'btn btn-secondary', 'data-action': 'close-modal' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', 'data-action': 'submit-publish-policy', 'data-id': policyId, 'data-version': latest ? latest.version : '' }, 'Publish'),
    ],
  });
  state.modalForm = { reason };
}

async function submitPublishPolicy(button, policyId) {
  const { reason } = state.modalForm || {};
  if (!reason) return;
  if (reason.value.trim().length < 3) {
    showMessage('error', 'A release reason of at least 3 characters is required.');
    return;
  }
  const version = Number(button.dataset.version);

  await runButton(button, async () => {
    await api(`/admin/policies/${encodeURIComponent(policyId)}/publish`, {
      method: 'POST',
      body: { version, reason: reason.value.trim() },
    });
    closeModal();
    showMessage('success', `Policy published as v${version}. Devices will receive a freshly signed envelope on their next fetch.`);
    await refreshAll();
    await loadPolicyDetail(policyId);
  });
}

async function newDraft(policyId) {
  if (!window.confirm('Create a new editable draft from the currently published version?')) return;
  const result = await api(`/admin/policies/${encodeURIComponent(policyId)}/new-draft`, { method: 'POST' });
  showMessage('success', `Draft v${result.draft_version} created. The published version remains active until this draft is published.`);
  await refreshAll();
  await loadPolicyDetail(policyId);
}

async function rollbackPolicyModal(policyId) {
  const detail = await api(`/admin/policies/${encodeURIComponent(policyId)}`);
  const select = h('select', { class: 'select' });
  // Only earlier published versions are valid rollback targets.  The current
  // version is excluded, and pending drafts cannot be selected at all.
  const versions = (detail.versions || []).filter((version) => version.version < detail.version);
  for (const version of versions) {
    select.append(
      h('option', { value: String(version.version) },
        `v${version.version}${version.rollback_of_version ? ` (rollback of v${version.rollback_of_version})` : ''} — ${version.reason || 'no reason'}`)
    );
  }
  if (versions.length > 0) select.value = String(versions[versions.length - 1].version);

  const reason = h('input', { class: 'input', type: 'text', maxlength: '500', placeholder: 'Rollback reason' });
  const body = h('div');
  body.append(
    h('div', { class: 'notice' },
      'Rollback publishes the selected content as a new, strictly greater version. Existing versions are never modified, so anti-downgrade enforcement remains intact.'),
    versions.length === 0
      ? h('div', { class: 'notice', style: 'border-color: rgba(239,68,68,0.35);' }, 'This policy has no earlier published version to roll back to.')
      : h('div', { class: 'field' }, h('label', null, 'Target version'), select),
    h('div', { class: 'field' }, h('label', null, 'Reason'), reason)
  );

  openModal({
    title: `Rollback ${detail.name}`,
    desc: 'No separate approval step is required, but the rollback actor must differ from the policy author. The action is audited.',
    body,
    footer: [
      h('button', { class: 'btn btn-secondary', 'data-action': 'close-modal' }, 'Cancel'),
      h('button', {
        class: 'btn btn-danger',
        'data-action': 'submit-rollback-policy',
        'data-id': policyId,
        disabled: versions.length === 0 ? 'disabled' : null,
      }, 'Publish rollback'),
    ],
  });
  state.modalForm = { select, reason };
}

async function submitRollbackPolicy(button, policyId) {
  const { select, reason } = state.modalForm || {};
  if (!select || !reason) return;
  if (reason.value.trim().length < 3) {
    showMessage('error', 'A rollback reason of at least 3 characters is required.');
    return;
  }
  const target = Number(select.value);

  await runButton(button, async () => {
    const result = await api(`/admin/policies/${encodeURIComponent(policyId)}/rollback`, {
      method: 'POST',
      body: { target_version: target, reason: reason.value.trim() },
    });
    closeModal();
    showMessage('success', `Rollback published as v${result.version}, based on v${result.rollback_of_version}.`);
    await refreshAll();
    await loadPolicyDetail(policyId);
  });
}

/* ------------------------------------------------------------ enrollment UI */

async function generateEnrollment() {
  const reasonInput = document.getElementById('enroll-reason');
  const ttl = Number(document.getElementById('enroll-ttl').value);
  const reason = reasonInput.value.trim();
  if (reason.length < 3) {
    showMessage('error', 'Enter a reason of at least 3 characters for the audit record.');
    return;
  }

  const result = await api('/admin/enrollment-codes', {
    method: 'POST',
    body: { expires_in_seconds: ttl, reason },
  });

  document.getElementById('generated-code').textContent = result.enrollment_code;
  document.getElementById('enrollment-result').hidden = false;
  startCountdown(result.expires_at);
  showMessage('success', 'Enrollment code generated. It can be used once and expires automatically.');
}

function startCountdown(expiresAt) {
  if (state.countdownTimer) clearInterval(state.countdownTimer);
  const target = new Date(expiresAt).getTime();
  const tick = () => {
    const element = document.getElementById('code-countdown');
    if (!element) return;
    const remaining = Math.max(0, Math.floor((target - Date.now()) / 1000));
    if (remaining === 0) {
      element.textContent = 'Expired — generate a new code.';
      if (state.countdownTimer) clearInterval(state.countdownTimer);
      state.countdownTimer = null;
      return;
    }
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    element.textContent = `Expires in ${minutes}m ${String(seconds).padStart(2, '0')}s`;
  };
  tick();
  state.countdownTimer = setInterval(tick, 1000);
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    showMessage('success', `${label} copied to the clipboard.`);
  } catch {
    showMessage('error', 'Clipboard access was denied. Select and copy the value manually.');
  }
}

/* ------------------------------------------------------------- exceptions UI */

async function populateExceptionDevices() {
  const select = document.getElementById('exception-device');
  if (!select) return;
  const previous = select.value;
  clear(select);
  const devices = state.devices.filter((device) => device.status !== 'revoked');
  if (devices.length === 0) {
    select.append(h('option', { value: '' }, 'No eligible devices'));
    await loadExceptionControls();
    return;
  }
  for (const device of devices) {
    select.append(h('option', { value: device.id }, `${device.display_name} (${shortId(device.id)})`));
  }
  if (previous && devices.some((device) => device.id === previous)) select.value = previous;
  await loadExceptionControls();
}

async function loadExceptionControls() {
  const deviceSelect = document.getElementById('exception-device');
  const controlSelect = document.getElementById('exception-control');
  if (!deviceSelect || !controlSelect) return;
  const previousControl = controlSelect.value;
  clear(controlSelect);
  const deviceId = deviceSelect.value;
  if (!deviceId) {
    controlSelect.append(h('option', { value: '' }, 'No device selected'));
    return;
  }
  try {
    const device = await api(`/admin/devices/${encodeURIComponent(deviceId)}`);
    if (!device.assigned_policy_id) {
      controlSelect.append(h('option', { value: '' }, 'Device has no assigned policy'));
      return;
    }
    const policy = await api(`/admin/policies/${encodeURIComponent(device.assigned_policy_id)}`);
    const controls = (policy.policy && policy.policy.controls) || [];
    for (const control of controls) {
      controlSelect.append(h('option', { value: control.control_id }, control.control_id));
    }
    if (controls.length === 0) {
      controlSelect.append(h('option', { value: '' }, 'Policy has no controls'));
    } else if (previousControl && controls.some((control) => control.control_id === previousControl)) {
      controlSelect.value = previousControl;
    }
  } catch (error) {
    controlSelect.append(h('option', { value: '' }, 'Unable to load controls'));
    showMessage('error', errorText(error));
  }
}

async function createException() {
  const deviceId = document.getElementById('exception-device').value;
  const controlId = document.getElementById('exception-control').value;
  const reason = document.getElementById('exception-reason').value.trim();
  const hours = Number(document.getElementById('exception-hours').value);

  if (!deviceId || !controlId) {
    showMessage('error', 'Select a device and control.');
    return;
  }
  if (reason.length < 5) {
    showMessage('error', 'An exception reason of at least 5 characters is required.');
    return;
  }
  if (!Number.isFinite(hours) || hours < 1 || hours > 2160) {
    showMessage('error', 'Duration must be between 1 and 2160 hours (90 days).');
    return;
  }

  const expiresAt = new Date(Date.now() + hours * 3600 * 1000).toISOString();
  await api('/admin/exceptions', {
    method: 'POST',
    body: { device_id: deviceId, control_id: controlId, reason, expires_at: expiresAt },
  });
  document.getElementById('exception-reason').value = '';
  showMessage('success', 'Exception created and recorded in the audit log.');
  await refreshAll();
}

async function revokeException(exceptionId) {
  const reason = window.prompt('Reason for revoking this exception:', '');
  if (!reason || reason.trim().length < 3) return;
  await api(`/admin/exceptions/${encodeURIComponent(exceptionId)}/revoke`, {
    method: 'POST',
    body: { reason: reason.trim() },
  });
  showMessage('success', 'Exception revoked.');
  await refreshAll();
}

/* -------------------------------------------------------------------- audit */

async function verifyAudit() {
  const result = await api('/admin/audit-events/verify');
  const banner = document.getElementById('audit-verify-result');
  const text = document.getElementById('audit-verify-text');
  banner.hidden = false;
  banner.className = result.valid ? 'banner banner-success' : 'banner banner-error';
  text.textContent = result.valid
    ? `Chain valid: ${result.checked} records verified. Head ${shortId(result.head, 24)}.`
    : `Chain invalid at ${result.broken_id}: ${result.reason}.`;
}

/* -------------------------------------------------------------- modal & run */

function openModal({ title, desc, body, footer }) {
  document.getElementById('modal-title').textContent = title || '';
  document.getElementById('modal-desc').textContent = desc || '';
  const bodyElement = document.getElementById('modal-body');
  clear(bodyElement);
  if (body) bodyElement.append(body);
  const footerElement = document.getElementById('modal-footer');
  clear(footerElement);
  if (footer) footerElement.append(...footer);
  document.getElementById('modal-backdrop').hidden = false;
  const firstInput = bodyElement.querySelector('input, textarea, select');
  if (firstInput) firstInput.focus();
}

function closeModal() {
  document.getElementById('modal-backdrop').hidden = true;
  state.modalForm = null;
}

async function runButton(button, action) {
  if (button) button.disabled = true;
  try {
    await action();
  } catch (error) {
    showMessage('error', errorText(error));
  } finally {
    if (button) button.disabled = false;
  }
}

/* ------------------------------------------------------------------ actions */

const actions = {
  refresh: async () => {
    await refreshAll();
    showMessage('success', 'State refreshed from the control plane.');
  },
  'dismiss-banner': () => {
    document.getElementById('global-banner').hidden = true;
  },
  'dismiss-message': () => hideMessage(),
  'open-tab': (button) => switchTab(button.dataset.tab),
  'open-enrollment': () => switchTab('enrollment'),
  'close-policy-detail': () => {
    state.selectedPolicyId = null;
    document.getElementById('policy-detail-card').hidden = true;
  },
  'inspect-device': async (button) => {
    await runButton(button, () => openDeviceModal(button.dataset.id));
  },
  'rotate-device': async (button) => {
    closeModal();
    await runButton(button, () => rotateDevice(button.dataset.id));
  },
  'revoke-device': async (button) => {
    await runButton(button, () => revokeDevice(button.dataset.id));
  },
  'create-policy': async (button) => {
    await runButton(button, () => createPolicyModal());
  },
  'submit-create-policy': async (button) => {
    await submitCreatePolicy(button);
  },
  'view-policy': async (button) => {
    await runButton(button, async () => {
      await loadPolicyDetail(button.dataset.id);
      switchTab('policies');
    });
  },
  'edit-policy': async (button) => {
    await runButton(button, () => editPolicyModal(button.dataset.id));
  },
  'submit-edit-policy': async (button) => {
    await submitEditPolicy(button, button.dataset.id);
  },
  'submit-policy': async (button) => {
    await runButton(button, () => submitPolicy(button.dataset.id));
  },
  'approve-policy': async (button) => {
    await runButton(button, () => approvePolicyModal(button.dataset.id));
  },
  'submit-approve-policy': async (button) => {
    await submitApprovePolicy(button, button.dataset.id);
  },
  'publish-policy': async (button) => {
    await runButton(button, () => publishPolicyModal(button.dataset.id));
  },
  'submit-publish-policy': async (button) => {
    await submitPublishPolicy(button, button.dataset.id);
  },
  'new-draft': async (button) => {
    await runButton(button, () => newDraft(button.dataset.id));
  },
  'rollback-policy': async (button) => {
    await runButton(button, () => rollbackPolicyModal(button.dataset.id));
  },
  'submit-rollback-policy': async (button) => {
    await submitRollbackPolicy(button, button.dataset.id);
  },
  'generate-enrollment': async (button) => {
    await runButton(button, generateEnrollment);
  },
  'copy-code': async () => {
    const code = document.getElementById('generated-code').textContent;
    if (code) await copyText(code, 'Enrollment code');
  },
  'copy-rotated-token': async () => {
    const token = document.getElementById('rotated-token');
    if (token) await copyText(token.textContent, 'Device credential');
  },
  'verify-audit': async (button) => {
    await runButton(button, verifyAudit);
  },
  'create-exception': async (button) => {
    await runButton(button, createException);
  },
  'revoke-exception': async (button) => {
    await runButton(button, () => revokeException(button.dataset.id));
  },
  'close-modal': () => closeModal(),
};

/* --------------------------------------------------------------------- boot */

function bindEvents() {
  document.addEventListener('click', (event) => {
    const navItem = event.target.closest('.nav-item[data-tab]');
    if (navItem) {
      switchTab(navItem.dataset.tab);
      return;
    }
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const handler = actions[button.dataset.action];
    if (!handler) return;
    event.preventDefault();
    runButton(button, () => handler(button));
  });

  document.getElementById('device-search').addEventListener('input', renderDevices);

  document.getElementById('dev-user').addEventListener('change', (event) => {
    state.user = event.target.value.trim() || 'dev-admin';
    saveIdentity();
    renderIdentity();
    refreshAll();
  });
  document.getElementById('dev-role').addEventListener('change', (event) => {
    state.role = event.target.value;
    saveIdentity();
    refreshAll();
  });
  document.getElementById('oidc-token').addEventListener('change', (event) => {
    state.token = event.target.value.trim();
    saveIdentity();
    refreshAll();
  });

  document.getElementById('exception-device').addEventListener('change', loadExceptionControls);

  document.getElementById('modal-backdrop').addEventListener('click', (event) => {
    if (event.target.id === 'modal-backdrop') closeModal();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeModal();
  });

  setInterval(() => {
    if (!document.hidden && document.getElementById('modal-backdrop').hidden) {
      refreshAll().catch((error) => showMessage('error', errorText(error)));
    }
  }, 15000);
}

async function boot() {
  loadIdentity();
  renderIdentity();

  try {
    const root = await fetch(`${API}`, { headers: { Accept: 'application/json' } }).then((response) => response.json());
    state.authMode = root.auth_mode === 'dev' ? 'dev' : 'oidc';
    if (Number.isFinite(root.stale_after_seconds)) state.staleAfterSeconds = root.stale_after_seconds;
    document.getElementById('api-version').textContent = `Version ${root.version || '—'}`;
    document.getElementById('global-banner-text').textContent =
      state.authMode === 'dev'
        ? 'Local development mode: administrator identity is taken from X-Dev-User / X-Dev-Role. This is only safe because APP_ENV=local. Device data shown here comes from the simulator and submitted read-backs, not from real Windows enforcement.'
        : 'OIDC mode: paste an access token with a WorkGuard role to call the admin API. Device data reflects submitted read-backs.';
  } catch (error) {
    showMessage('error', `Cannot reach the control plane: ${errorText(error)}`);
  }

  renderIdentity();
  bindEvents();
  await refreshAll();
}

boot();
